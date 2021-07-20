// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Main Stronghold Interface
//!
//! All functionality can be accessed from the interface. Functions
//! are provided in an asynchronous way, and should be run by the
//! actor's system [`SystemRunner`].

// TODO: add access to runtime of actix

use futures::{future::RemoteHandle, io::Read};

// // TODO remove
// use riker::*;

use actix::{Actor, Addr, Supervisor, System, SystemRunner, SystemService};

// use futures::{
//     channel::mpsc::{channel, Receiver, Sender},
//     future::RemoteHandle,
// };

use std::{collections::HashMap, path::PathBuf, time::Duration};
use stronghold_utils::ask;
use zeroize::Zeroize;

use crate::{
    actors::{
        secure_messages, GetClient, HasClient, InsertClient, InternalActor, ProcResult, Procedure, Registry, SHRequest,
        SHResults, SecureClient,
    },
    internals, line_error,
    state::{
        client::Client,
        snapshot::{Snapshot, SnapshotState},
    },
    utils::{LoadFromPath, StatusMessage, StrongholdFlags, VaultFlags},
    Location, Provider,
};
use engine::vault::{ClientId, RecordId};
use engine::vault::{RecordHint, VaultId};

#[cfg(feature = "communication")]
use comm::*;

/// communication feature relevant imports are bundled here.
mod comm {
    pub use crate::actors::SHRequestPermission;
    pub use crate::utils::ResultMessage;
    pub use futures::{executor::block_on, StreamExt};

    pub use communication::{
        actor::{
            CommunicationActor, CommunicationActorConfig, CommunicationRequest, CommunicationResults,
            EstablishedConnection, FirewallPermission, FirewallRule, RelayDirection, RequestDirection,
            VariantPermission,
        },
        behaviour::BehaviourConfig,
        libp2p::{Keypair, Multiaddr, PeerId},
    };
}

/// The main type for the Stronghold System.  Used as the entry point for the actor model.  Contains various pieces of
/// metadata to interpret the data in the vault and store.
pub struct Stronghold<A>
where
    A: Actor,
{
    // we can skip this optional reference, since we won't need the system to drive
    // the api. Since the user must provide it's own runtime.
    // pub system: Option<SystemRunner>,
    registry: Addr<Registry>,
    target: Addr<SecureClient<internals::Provider>>, // check dependency on provider

    #[cfg(feature = "communication")]
    communication_actor: Option<Addr<A>>,
}

impl<A: Actor> Stronghold<A> {
    /// Initializes a new instance of the system.  Sets up the first client actor. Accepts an optional [`SystemRunner`], the first
    /// client_path: `Vec<u8>` and any `StrongholdFlags` which pertain to the first actor.

    /// IDEAS
    ///
    /// - The [`SystemRunner`] is not being used directly by stronghold, but is being initialized
    ///   on the first run.
    /// - The initialization function can be made asynchronous as well, getting rid of internal
    ///   explicit blocking
    /// -
    pub fn init_stronghold_system(
        system: Option<SystemRunner>,
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> Result<Self, anyhow::Error> {
        // create client actor
        let client_id =
            ClientId::load_from_path(&client_path, &client_path).expect(crate::Error::IDError.to_string().as_str());

        let runner = system.unwrap_or_else(|| System::new());

        // the registry will be run as a system service
        let registry = Registry::from_registry();
        let snapshot = Snapshot::new(SnapshotState::default()).start();

        // we need to block for the target client actor
        let target = match runner.block_on(registry.send(InsertClient { id: client_id }))? {
            Ok(addr) => addr,
            Err(e) => return Err(anyhow::anyhow!(e)),
        };

        Ok(Self {
            // system,
            registry,
            target,

            #[cfg(feature = "communication")]
            communication_actor: None,
        })
    }

    /// Spawns a new set of actors for the Stronghold system. Accepts the client_path: `Vec<u8>` and the options:
    /// `StrongholdFlags`
    pub async fn spawn_stronghold_actor(
        &mut self,
        client_path: Vec<u8>,
        _options: Vec<StrongholdFlags>,
    ) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());

        if let Ok(result) = self.registry.send(GetClient { id: client_id }).await {
            match result {
                Some(client) => {
                    self.target = client;
                }
                None => {
                    if let Ok(result) = self.registry.send(InsertClient { id: client_id }).await {
                        self.target = match result {
                            Ok(client) => client,
                            Err(e) => return StatusMessage::Error("".to_string()),
                        };
                    }
                }
            }
        };

        StatusMessage::OK
    }

    /// Switches the actor target to another actor in the system specified by the client_path: `Vec<u8>`.
    pub async fn switch_actor_target(&mut self, client_path: Vec<u8>) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path.clone()).expect(line_error!());

        if let Ok(result) = self.registry.send(GetClient { id: client_id }).await {
            match result {
                Some(client) => self.target = client,
                None => return StatusMessage::Error("Could not find actor with provided client path".into()),
            }

            #[cfg(feature = "communication")]
            if let Some(comm) = &self.communication_actor {
                // TODO set reference to client actor inside the communication actor
            }
        }

        StatusMessage::OK
    }

    /// Writes data into the Stronghold. Uses the current target actor as the client and writes to the specified
    /// location of `Location` type. The payload must be specified as a `Vec<u8>` and a `RecordHint` can be provided.
    /// Also accepts `VaultFlags` for when a new Vault is created.
    pub async fn write_to_vault(
        &self,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> StatusMessage {
        // TODO move to top
        use crate::actors::secure_messages::{CheckVault, CreateVault, WriteToVault};

        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        // new actix impl
        match self.target.send(CheckVault { vault_path }).await {
            Ok(result) => match result {
                Ok(_) => {
                    // exists

                    self.target
                        .send(WriteToVault {
                            // vault_id,
                            // record_id,
                            location,
                            payload,
                            hint,
                        })
                        .await;
                }
                Err(_) => {
                    // does not exist

                    match self
                        .target
                        .send(CreateVault {
                            location: location.clone(),
                        })
                        .await
                    {
                        Ok(_) => {
                            // write to vault

                            if let Ok(result) = self
                                .target
                                .send(WriteToVault {
                                    location,
                                    payload,
                                    hint,
                                })
                                .await
                            {
                            } else {
                                return StatusMessage::Error("Error Writing data".into());
                            }
                        }
                        Err(e) => {
                            return StatusMessage::Error("Cannot create new vault".into());
                        }
                    }
                }
            },
            Err(_) => {}
        }

        StatusMessage::Error("Failed to write the data".into())

        // old riker impl
        // if let SHResults::ReturnExistsVault(b) =
        //     ask(&self.system, &self.target, SHRequest::CheckVault(vault_path.clone())).await
        // {
        //     // check if vault exists
        //     if b {
        //         if let SHResults::ReturnWriteVault(status) = ask(
        //             &self.system,
        //             &self.target,
        //             SHRequest::WriteToVault {
        //                 location: location.clone(),
        //                 payload: payload.clone(),
        //                 hint,
        //             },
        //         )
        //         .await
        //         {
        //             return status;
        //         } else {
        //             return StatusMessage::Error("Error Writing data".into());
        //         };
        //     } else {
        //         // no vault so create new one before writing.
        //         if let SHResults::ReturnCreateVault(status) =
        //             ask(&self.system, &self.target, SHRequest::CreateNewVault(location.clone())).await
        //         {
        //             status
        //         } else {
        //             return StatusMessage::Error("Invalid Message".into());
        //         };

        //         if let SHResults::ReturnWriteVault(status) = ask(
        //             &self.system,
        //             &self.target,
        //             SHRequest::WriteToVault {
        //                 location,
        //                 payload,
        //                 hint,
        //             },
        //         )
        //         .await
        //         {
        //             return status;
        //         } else {
        //             return StatusMessage::Error("Error Writing data".into());
        //         };
        //     }
        // };

        // StatusMessage::Error("Failed to write the data".into())
    }

    /// Writes data into an insecure cache.  This method, accepts a `Location`, a `Vec<u8>` and an optional `Duration`.
    /// The lifetime allows the data to be deleted after the specified duration has passed.  If not lifetime is
    /// specified, the data will persist until it is manually deleted or over-written. Note: One store is mapped to
    /// one client. Can specify the same location across multiple clients.
    pub async fn write_to_store(
        &self,
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StatusMessage {
        // TODO move to top
        use crate::actors::secure_messages::WriteToStore;

        match self
            .target
            .send(WriteToStore {
                location,
                payload,
                lifetime,
            })
            .await
        {
            Ok(status) => status.into(),
            Err(e) => StatusMessage::Error("Failed to write to the store".into()),
        }

        // let res: SHResults = ask(
        //     &self.system,
        //     &self.target,
        //     SHRequest::WriteToStore {
        //         location,
        //         payload,
        //         lifetime,
        //     },
        // )
        // .await;

        // if let SHResults::ReturnWriteStore(status) = res {
        //     status
        // } else {
        //     StatusMessage::Error("Failed to write to the store".into())
        // }
    }

    /// A method that reads from an insecure cache.  This method, accepts a `Location` and returns the payload in the
    /// form of a `Vec<u8>`.  If the location does not exist, an empty vector will be returned along with an error
    /// `StatusMessage`.  Note: One store is mapped to
    /// one client. Can specify the same location across multiple clients.
    pub async fn read_from_store(&self, location: Location) -> (Vec<u8>, StatusMessage) {
        // TODO move to top
        use crate::actors::secure_messages::ReadFromStore;

        match self.target.send(ReadFromStore { location }).await {
            Ok(result) => match result {
                Ok(data) => (data, StatusMessage::OK),
                Err(e) => (Vec::new(), StatusMessage::Error(format!("{:?}", e))),
            },
            Err(e) => (Vec::new(), StatusMessage::Error(format!("{:?}", e))),
        }

        // let res: SHResults = ask(&self.system, &self.target, SHRequest::ReadFromStore { location }).await;

        // if let SHResults::ReturnReadStore(payload, status) = res {
        //     (payload, status)
        // } else {
        //     (vec![], StatusMessage::Error("Failed to read from the store".into()))
        // }
    }

    /// A method to delete data from an insecure cache. This method, accepts a `Location` and returns a `StatusMessage`.
    /// Note: One store is mapped to one client. Can specify the same location across multiple clients.
    pub async fn delete_from_store(&self, location: Location) -> StatusMessage {
        // TODO move to top
        use crate::actors::secure_messages::DeleteFromStore;

        match self.target.send(DeleteFromStore { location }).await {
            Ok(result) => match result {
                Ok(_) => StatusMessage::OK,
                Err(e) => StatusMessage::Error(format!("{:?}", e)),
            },
            Err(e) => StatusMessage::Error("Failed to delete from the store".into()),
        }

        // let res: SHResults = ask(&self.system, &self.target, SHRequest::DeleteFromStore(location)).await;

        // if let SHResults::ReturnDeleteStore(status) = res {
        //     status
        // } else {
        //     StatusMessage::Error("Failed to delete from the store".into())
        // }
    }

    /// Revokes the data from the specified location of type `Location`. Revoked data is not readable and can be removed
    /// from a vault with a call to `garbage_collect`.  if the `should_gc` flag is set to `true`, this call with
    /// automatically cleanup the revoke. Otherwise, the data is just marked as revoked.
    pub async fn delete_data(&self, location: Location, should_gc: bool) -> StatusMessage {
        use crate::actors::secure_messages::{GarbageCollect, RevokeData};

        // new actix impl
        match self
            .target
            .send(RevokeData {
                location: location.clone(),
            })
            .await
        {
            Ok(result) => match result {
                Ok(ok) if should_gc => match self.target.send(GarbageCollect { location }).await {
                    Ok(result) => match result {
                        Ok(_) => StatusMessage::OK,
                        Err(e) => StatusMessage::Error(format!("{:?}", e)),
                    },
                    Err(e) => StatusMessage::Error("Failed to garbage collect the vault".into()),
                },
                Ok(ok) => StatusMessage::OK,
                Err(e) => StatusMessage::Error("Could not revoke data".into()),
            },
            Err(e) => StatusMessage::Error("Could not revoke data".into()),
        }

        // old riker impl
        // let vault_path = location.vault_path().to_vec();
        // let status;

        // if should_gc {
        //     let _ = if let SHResults::ReturnRevoke(status) =
        //         ask(&self.system, &self.target, SHRequest::RevokeData { location }).await
        //     {
        //         status
        //     } else {
        //         return StatusMessage::Error("Could not revoke data".into());
        //     };

        //     status = if let SHResults::ReturnGarbage(status) = ask(
        //         &self.system,
        //         &self.target,
        //         SHRequest::GarbageCollect(vault_path.clone()),
        //     )
        //     .await
        //     {
        //         status
        //     } else {
        //         return StatusMessage::Error("Failed to garbage collect the vault".into());
        //     };
        // } else {
        //     status = if let SHResults::ReturnRevoke(status) =
        //         ask(&self.system, &self.target, SHRequest::RevokeData { location }).await
        //     {
        //         status
        //     } else {
        //         return StatusMessage::Error("Could not revoke data".into());
        //     };
        // }

        // status
    }

    /// Garbage collects any revokes in a Vault based on the given vault_path and the current target actor.
    pub async fn garbage_collect(&self, vault_path: Vec<u8>) -> StatusMessage {
        use crate::actors::secure_messages::GarbageCollect;

        match self
            .target
            .send(GarbageCollect {
                location: Location::Generic {
                    vault_path,
                    record_path: Vec::new(), // this will be dropped.
                },
            })
            .await
        {
            Ok(result) => match result {
                Ok(_) => StatusMessage::OK,
                Err(e) => StatusMessage::Error(format!("{:?}", e)),
            },
            Err(e) => StatusMessage::Error("Failed to garbage collect the vault".into()),
        }

        // if let SHResults::ReturnGarbage(status) =
        //     ask(&self.system, &self.target, SHRequest::GarbageCollect(vault_path)).await
        // {
        //     status
        // } else {
        //     StatusMessage::Error("Failed to garbage collect the vault".into())
        // }
    }

    /// Returns a list of the available `RecordId` and `RecordHint` values in a vault by the given `vault_path`.
    pub async fn list_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        vault_path: V,
    ) -> (Vec<(RecordId, RecordHint)>, StatusMessage) {
        use crate::actors::secure_messages::ListIds;

        match self
            .target
            .send(ListIds {
                vault_path: vault_path.into(),
            })
            .await
        {
            Ok(success) => match success {
                Ok(result) => (result, StatusMessage::OK),
                Err(e) => (Vec::new(), StatusMessage::Error(format!("{:?}", e))),
            },
            Err(e) => (
                Vec::new(),
                StatusMessage::Error("Failed to list hints and indexes from the vault".into()),
            ),
        }

        // if let SHResults::ReturnList(ids, status) =
        //     ask(&self.system, &self.target, SHRequest::ListIds(vault_path.into())).await
        // {
        //     (ids, status)
        // } else {
        //     (
        //         vec![],
        //         StatusMessage::Error("Failed to list hints and indexes from the vault".into()),
        //     )
        // }
    }

    /// Executes a runtime command given a `Procedure`.  Returns a `ProcResult` based off of the control_request
    /// specified.
    pub async fn runtime_exec(&self, control_request: Procedure) -> ProcResult {
        // TODO this might be the biggest change in adapting the
        // interface to actix. as procedures are split among structures
        // inside the secure client, passed arguments to execute a procedure
        // may be mapped to internal procedures.

        use crate::actors::secure_procedures::{
            BIP39Generate, BIP39Recover, Ed25519PublicKey, Ed25519Sign, SLIP10DeriveFromKey, SLIP10DeriveFromSeed,
            SLIP10Generate,
        };

        match control_request {
            Procedure::SLIP10Generate {
                output,
                hint,
                size_bytes,
            } => todo!(),

            Procedure::SLIP10Derive {
                chain,
                input,
                output,
                hint,
            } => todo!(),
            Procedure::BIP39Recover {
                mnemonic,
                passphrase,
                output,
                hint,
            } => todo!(),
            Procedure::BIP39Generate {
                passphrase,
                output,
                hint,
            } => todo!(),
            Procedure::BIP39MnemonicSentence { seed } => todo!(),
            Procedure::Ed25519PublicKey { private_key } => todo!(),
            Procedure::Ed25519Sign { private_key, msg } => todo!(),
        }

        // let shr = ask(&self.system, &self.target, SHRequest::ControlRequest(control_request)).await;
        // match shr {
        //     SHResults::ReturnControlRequest(pr) => pr,
        //     _ => ProcResult::Error("Invalid communication event".into()),
        // }
    }

    /// Checks whether a record exists in the client based off of the given `Location`.
    pub async fn record_exists(&self, location: Location) -> bool {
        if let SHResults::ReturnExistsRecord(b) = ask(
            &self.system,
            &self.target,
            SHRequest::CheckRecord {
                location: location.clone(),
            },
        )
        .await
        {
            b
        } else {
            false
        }
    }

    /// checks whether a vault exists in the client.
    pub async fn vault_exists(&self, location: Location) -> bool {
        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();

        if let SHResults::ReturnExistsVault(b) =
            ask(&self.system, &self.target, SHRequest::CheckVault(vault_path)).await
        {
            b
        } else {
            false
        }
    }

    /// Reads data from a given snapshot file.  Can only read the data for a single `client_path` at a time. If the new
    /// actor uses a new `client_path` the former client path may be passed into the function call to read the data into
    /// that actor. Also requires keydata to unlock the snapshot. A filename and filepath can be specified. The Keydata
    /// should implement and use Zeroize.
    pub async fn read_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        client_path: Vec<u8>,
        former_client_path: Option<Vec<u8>>,
        keydata: &T,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path, &client_path).expect(line_error!());

        let former_cid = former_client_path.map(|cp| ClientId::load_from_path(&cp, &cp).expect(line_error!()));

        let mut key: [u8; 32] = [0u8; 32];

        let keydata = keydata.as_ref();

        key.copy_from_slice(keydata);

        if let SHResults::ReturnReadSnap(status) = ask(
            &self.system,
            &self.target,
            SHRequest::ReadSnapshot {
                key,
                filename,
                path,
                cid: client_id,
                former_cid,
            },
        )
        .await
        {
            status
        } else {
            StatusMessage::Error("Unable to read snapshot".into())
        }
    }

    /// Writes the entire state of the `Stronghold` into a snapshot.  All Actors and their associated data will be
    /// written into the specified snapshot. Requires keydata to encrypt the snapshot and a filename and path can be
    /// specified. The Keydata should implement and use Zeroize.
    pub async fn write_all_to_snapshot<T: Zeroize + AsRef<Vec<u8>>>(
        &mut self,
        keydata: &T,
        filename: Option<String>,
        path: Option<PathBuf>,
    ) -> StatusMessage {
        let num_of_actors = self.clients.len();

        let mut futures = vec![];
        let mut key: [u8; 32] = [0u8; 32];

        let keydata = keydata.as_ref();

        key.copy_from_slice(keydata);

        if num_of_actors != 0 {
            for actor in self.clients.values() {
                let res: RemoteHandle<SHResults> = ask(&self.system, actor, SHRequest::FillSnapshot);
                futures.push(res);
            }
        } else {
            return StatusMessage::Error("Unable to write snapshot without any actors.".into());
        }

        for fut in futures {
            fut.await;
        }

        let res: SHResults = ask(
            &self.system,
            &self.target,
            SHRequest::WriteSnapshot { key, filename, path },
        )
        .await;

        if let SHResults::ReturnWriteSnap(status) = res {
            status
        } else {
            StatusMessage::Error("Unable to write snapshot".into())
        }
    }

    /// Used to kill a stronghold actor or clear the cache of the given actor system based on the client_path. If
    /// `kill_actor` is `true` both the internal actor and the client actor will be killed.  Otherwise, the cache of the
    /// current target actor will be cleared.
    pub async fn kill_stronghold(&mut self, client_path: Vec<u8>, kill_actor: bool) -> StatusMessage {
        let client_id = ClientId::load_from_path(&client_path.clone(), &client_path).expect(line_error!());
        self.switch_actor_target(client_path).await;

        if kill_actor {
            self.clients.remove(&client_id);
        }

        if let SHResults::ReturnClearCache(status) =
            ask(&self.system, &self.target, SHRequest::ClearCache { kill: kill_actor }).await
        {
            status
        } else {
            StatusMessage::Error("Unable to clear cache".into())
        }
    }

    /// Unimplemented until Policies are implemented.
    #[allow(dead_code)]
    fn check_config_flags() {
        unimplemented!()
    }

    /// A test function for reading data from a vault.
    #[cfg(test)]
    pub async fn read_secret(&self, location: Location) -> (Option<Vec<u8>>, StatusMessage) {
        let res: SHResults = ask(&self.system, &self.target, SHRequest::ReadFromVault { location }).await;

        if let SHResults::ReturnReadVault(payload, status) = res {
            (Some(payload), status)
        } else {
            (None, StatusMessage::Error("Unable to read data".into()))
        }
    }
}

#[cfg(feature = "communication_need_update")]
impl<A: Actor> Stronghold<A> {
    /// Spawn the communication actor and swarm with a pre-existing keypair
    /// Per default, the firewall allows all outgoing, and reject all incoming requests.
    pub fn spawn_communication_with_keypair(&mut self, keypair: Keypair) -> StatusMessage {
        if self.communication_actor.is_some() {
            return StatusMessage::Error(String::from("Communication was already spawned"));
        }

        let behaviour_config = BehaviourConfig::default();
        let actor_config = CommunicationActorConfig {
            client: self.target.clone(),
            firewall_default_in: FirewallPermission::all(),
            firewall_default_out: FirewallPermission::all(),
        };

        let communication_actor = self
            .system
            .actor_of_args::<CommunicationActor<_, SHResults, _, _>, _>(
                "communication",
                (keypair, actor_config, behaviour_config),
            )
            .expect(line_error!());
        self.communication_actor = Some(communication_actor);
        StatusMessage::OK
    }

    /// Spawn the communication actor and swarm.
    /// Per default, the firewall allows all outgoing, and reject all incoming requests.
    pub fn spawn_communication(&mut self) -> StatusMessage {
        self.spawn_communication_with_keypair(Keypair::generate_ed25519())
    }

    /// Gracefully stop the communication actor and swarm
    pub fn stop_communication(&mut self) {
        if let Some(communication_actor) = self.communication_actor.as_ref() {
            self.system.stop(communication_actor);
        }
    }

    /// Start listening on the swarm to the given address. If not address is provided, it will be assigned by the OS.
    pub async fn start_listening(&self, addr: Option<Multiaddr>) -> ResultMessage<Multiaddr> {
        match self
            .ask_communication_actor(CommunicationRequest::StartListening(addr))
            .await
        {
            Ok(CommunicationResults::StartListeningResult(Ok(addr))) => ResultMessage::Ok(addr),
            Ok(CommunicationResults::StartListeningResult(Err(_))) => ResultMessage::Error("Listener Error".into()),
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
    }

    /// Stop listening on the swarm.
    pub async fn stop_listening(&self) -> StatusMessage {
        match self.ask_communication_actor(CommunicationRequest::RemoveListener).await {
            Ok(CommunicationResults::RemoveListenerAck) => StatusMessage::OK,
            Ok(_) => StatusMessage::Error("Invalid communication actor response".into()),
            Err(err) => StatusMessage::Error(err),
        }
    }

    ///  Get the peer id, listening addresses and connection info of the local peer
    pub async fn get_swarm_info(
        &self,
    ) -> ResultMessage<(PeerId, Vec<Multiaddr>, Vec<(PeerId, EstablishedConnection)>)> {
        match self.ask_communication_actor(CommunicationRequest::GetSwarmInfo).await {
            Ok(CommunicationResults::SwarmInfo {
                peer_id,
                listeners,
                connections,
            }) => ResultMessage::Ok((peer_id, listeners, connections)),
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
    }

    /// Add dial information for a remote peers.
    /// This will attempt to connect the peer directly either by the address if one is provided, or by peer id
    /// if the peer is already known e.g. from multicast DNS.
    /// If the peer is not a relay and can not be reached directly, it will be attempted to reach it via the relays,
    /// if there are any.
    /// Relays can be used to listen for incoming request, or to connect to a remote peer that can not
    /// be reached directly, and is listening to the same relay.
    /// Once the peer was successfully added, it can be used as target for operations on the remote stronghold.
    pub async fn add_peer(
        &self,
        peer_id: PeerId,
        addr: Option<Multiaddr>,
        is_relay: Option<RelayDirection>,
    ) -> ResultMessage<PeerId> {
        match self
            .ask_communication_actor(CommunicationRequest::AddPeer {
                peer_id,
                addr,
                is_relay,
            })
            .await
        {
            Ok(CommunicationResults::AddPeerResult(Ok(peer_id))) => ResultMessage::Ok(peer_id),
            Ok(CommunicationResults::AddPeerResult(Err(err))) => {
                ResultMessage::Error(format!("Error connecting peer: {:?}", err))
            }
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
    }

    /// Set / overwrite the direction for which relay is used.
    /// RelayDirection::Dialing adds the relay to the list of relay nodes that are tried if a peer can not
    /// be reached directly.
    /// RelayDirection::Listening connect the local system with the given relay and allows that it can
    /// be reached by remote peers that use the same relay for dialing.
    /// The relay has to be added beforehand with its multi-address via the `add_peer` method.
    pub async fn change_relay_direction(&self, peer_id: PeerId, direction: RelayDirection) -> ResultMessage<PeerId> {
        match self
            .ask_communication_actor(CommunicationRequest::ConfigRelay { peer_id, direction })
            .await
        {
            Ok(CommunicationResults::ConfigRelayResult(Ok(peer_id))) => ResultMessage::Ok(peer_id),
            Ok(CommunicationResults::ConfigRelayResult(Err(err))) => {
                ResultMessage::Error(format!("Error connecting peer: {:?}", err))
            }
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
    }

    /// Remove a relay so that it will not be used anymore for dialing or listening.
    pub async fn remove_relay(&self, peer_id: PeerId) -> StatusMessage {
        match self
            .ask_communication_actor(CommunicationRequest::RemoveRelay(peer_id))
            .await
        {
            Ok(CommunicationResults::RemoveRelayAck) => StatusMessage::OK,
            Ok(_) => ResultMessage::Error("Invalid communication actor response".into()),
            Err(err) => ResultMessage::Error(err),
        }
    }

    /// Allow all requests from the given peers, optionally also set default to allow all.
    pub async fn allow_all_requests(&self, peers: Vec<PeerId>, set_default: bool) -> StatusMessage {
        let rule = FirewallRule::SetRules {
            direction: RequestDirection::In,
            peers,
            set_default,
            permission: FirewallPermission::all(),
        };
        self.configure_firewall(rule).await
    }

    /// Change or add rules in the firewall to allow the given requests for the peers, optionally also change the
    /// default rule to allow it.
    /// The `SHRequestPermission` copy the `SHRequest` with Unit-type variants with individual permission, e.g.
    /// ```no_run
    /// use iota_stronghold::SHRequestPermission;
    ///
    /// let permissions = vec![SHRequestPermission::CheckVault, SHRequestPermission::CheckRecord];
    /// ```
    /// Existing permissions for other `SHRequestPermission`s will not be changed by this.
    /// If no rule has been set for a given peer, the default rule will be used as basis.
    pub async fn allow_requests(
        &self,
        peers: Vec<PeerId>,
        change_default: bool,
        requests: Vec<SHRequestPermission>,
    ) -> StatusMessage {
        let rule = FirewallRule::AddPermissions {
            direction: RequestDirection::In,
            peers,
            change_default,
            permissions: requests.iter().map(|req| req.permission()).collect(),
        };
        self.configure_firewall(rule).await
    }

    /// Change or add rules in the firewall to reject the given requests from the peers, optionally also remove the
    /// permission from the default rule.
    /// The `SHRequestPermission` copy the `SHRequest` with Unit-type variants with individual permission, e.g.
    /// ```no_run
    /// use iota_stronghold::SHRequestPermission;
    ///
    /// let permissions = vec![SHRequestPermission::CheckVault, SHRequestPermission::CheckRecord];
    /// ```
    /// Existing permissions for other `SHRequestPermission`s will not be changed
    /// by this. If no rule has been set for a given peer, the default rule will be used as basis.
    pub async fn reject_requests(
        &self,
        peers: Vec<PeerId>,
        change_default: bool,
        requests: Vec<SHRequestPermission>,
    ) -> StatusMessage {
        let rule = FirewallRule::RemovePermissions {
            direction: RequestDirection::In,
            peers,
            change_default,
            permissions: requests.iter().map(|req| req.permission()).collect(),
        };
        self.configure_firewall(rule).await
    }

    /// Configure the firewall to reject all requests from the given peers, optionally also set default rule to reject
    /// all.
    pub async fn reject_all_requests(&self, peers: Vec<PeerId>, set_default: bool) -> StatusMessage {
        let rule = FirewallRule::SetRules {
            direction: RequestDirection::In,
            peers,
            set_default,
            permission: FirewallPermission::none(),
        };
        self.configure_firewall(rule).await
    }

    /// Remove peer specific rules from the firewall configuration.
    pub async fn remove_firewall_rules(&self, peers: Vec<PeerId>) -> StatusMessage {
        let rule = FirewallRule::RemoveRule {
            direction: RequestDirection::In,
            peers,
        };
        self.configure_firewall(rule).await
    }

    /// Write to the vault of a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn write_remote_vault(
        &self,
        peer_id: PeerId,
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
        _options: Vec<VaultFlags>,
    ) -> StatusMessage {
        let vault_path = &location.vault_path();
        let vault_path = vault_path.to_vec();
        // check if vault exists
        let vault_exists = match self
            .ask_remote(peer_id, SHRequest::CheckVault(vault_path.clone()))
            .await
        {
            Ok(SHResults::ReturnExistsVault(b)) => b,
            Ok(_) => return StatusMessage::Error("Failed to check at remote if vault exists".into()),
            Err(err) => return StatusMessage::Error(err),
        };
        if !vault_exists {
            // no vault so create new one before writing.
            match self
                .ask_remote(peer_id, SHRequest::CreateNewVault(location.clone()))
                .await
            {
                Ok(SHResults::ReturnCreateVault(_)) => {}
                Ok(_) => return StatusMessage::Error("Failed to create vault at remote".into()),
                Err(err) => return StatusMessage::Error(err),
            };
        }
        // write data
        match self
            .ask_remote(
                peer_id,
                SHRequest::WriteToVault {
                    location: location.clone(),
                    payload: payload.clone(),
                    hint,
                },
            )
            .await
        {
            Ok(SHResults::ReturnWriteVault(status)) => status,
            Ok(_) => StatusMessage::Error("Failed to write the data at remote vault".into()),
            Err(err) => StatusMessage::Error(err),
        }
    }

    /// Write to the store of a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn write_to_remote_store(
        &self,
        peer_id: PeerId,
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    ) -> StatusMessage {
        match self
            .ask_remote(
                peer_id,
                SHRequest::WriteToStore {
                    location,
                    payload,
                    lifetime,
                },
            )
            .await
        {
            Ok(SHResults::ReturnWriteStore(status)) => status,
            Ok(_) => StatusMessage::Error("Failed to write at the remote store".into()),
            Err(err) => StatusMessage::Error(err),
        }
    }

    /// Read from the store of a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn read_from_remote_store(&self, peer_id: PeerId, location: Location) -> (Vec<u8>, StatusMessage) {
        match self.ask_remote(peer_id, SHRequest::ReadFromStore { location }).await {
            Ok(SHResults::ReturnReadStore(payload, status)) => (payload, status),
            Ok(_) => (
                vec![],
                StatusMessage::Error("Failed to read at the remote store".into()),
            ),
            Err(err) => (vec![], StatusMessage::Error(err)),
        }
    }

    /// Returns a list of the available records and their `RecordHint` values of a remote vault.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn list_remote_hints_and_ids<V: Into<Vec<u8>>>(
        &self,
        peer_id: PeerId,
        vault_path: V,
    ) -> (Vec<(RecordId, RecordHint)>, StatusMessage) {
        match self.ask_remote(peer_id, SHRequest::ListIds(vault_path.into())).await {
            Ok(SHResults::ReturnList(ids, status)) => (ids, status),
            Ok(_) => (
                vec![],
                StatusMessage::Error("Failed to list hints and indexes from at remote vault".into()),
            ),
            Err(err) => (vec![], StatusMessage::Error(err)),
        }
    }

    /// Executes a runtime command at a remote Stronghold.
    /// It is required that the peer has successfully been added with the `add_peer` method.
    pub async fn remote_runtime_exec(&self, peer_id: PeerId, control_request: Procedure) -> ProcResult {
        match self
            .ask_remote(peer_id, SHRequest::ControlRequest(control_request))
            .await
        {
            Ok(SHResults::ReturnControlRequest(pr)) => pr,
            Ok(_) => ProcResult::Error("Invalid procedure result".into()),
            Err(err) => ProcResult::Error(err),
        }
    }

    // Wrap the SHRequest in an CommunicationRequest::RequestMsg and send it to the communication actor, to send it to
    // the remote peer. Fails if no communication actor is present, if sending the request failed or if an invalid event
    // was returned from the communication actor,
    async fn ask_remote(&self, peer_id: PeerId, request: SHRequest) -> Result<SHResults, String> {
        match self
            .ask_communication_actor(CommunicationRequest::RequestMsg { peer_id, request })
            .await
        {
            Ok(CommunicationResults::RequestMsgResult(Ok(ok))) => Ok(ok),
            Ok(CommunicationResults::RequestMsgResult(Err(e))) => Err(format!("Error sending request to peer {:?}", e)),
            Ok(_) => Err("Invalid communication actor response".into()),
            Err(err) => Err(err),
        }
    }

    // Send a request to the communication actor to configure the firewall by adding, changing or removing rules.
    async fn configure_firewall(&self, rule: FirewallRule) -> StatusMessage {
        match self
            .ask_communication_actor(CommunicationRequest::ConfigureFirewall(rule))
            .await
        {
            Ok(CommunicationResults::ConfigureFirewallAck) => StatusMessage::OK,
            Ok(_) => StatusMessage::Error("Invalid communication actor response".into()),
            Err(err) => StatusMessage::Error(err),
        }
    }

    // Send request to communication actor, fails if none is present.
    async fn ask_communication_actor(
        &self,
        request: CommunicationRequest<SHRequest, ClientMsg>,
    ) -> Result<CommunicationResults<SHResults>, String> {
        if let Some(communication_actor) = self.communication_actor.as_ref() {
            let res = ask(&self.system, communication_actor, request).await;
            Ok(res)
        } else {
            Err(String::from("No communication spawned"))
        }
    }

    // Keeps stronghold in a running state. This call is blocking.
    //
    // This function accepts an optional function for more control over how long
    // stronghold shall block.
    // #[cfg(test)]
    // pub fn keep_alive<F>(&self, callback: Option<F>)
    // where
    //     F: FnOnce() -> Result<(), Box<dyn std::error::Error>>,
    // {
    //     match callback {
    //         Some(cb) => {
    //             block_on(async {
    //                 cb().expect("Calling blocker function failed");
    //             });
    //         }
    //         None => {
    //             // create a channel, read from it, but never write.
    //             // this might be a trivial method to keep an instance running.
    //             let (_tx, rx): (Sender<usize>, Receiver<usize>) = channel(1);

    //             let waiter = async {
    //                 rx.map(|f| f).collect::<Vec<usize>>().await;
    //             };
    //             block_on(waiter);
    //         }
    //     }
    // }
}
