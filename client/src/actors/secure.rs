// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Actor module
//!
//! The secure actor runs as service, isolates contained data, and synchronizes
//! across multiple accesses.

// TODO - move functions from internal / client

pub use crate::{
    internals::Provider,
    state::{
        client::{Client, Store},
        key_store::KeyStore,
        secure::SecureClient,
        snapshot::Snapshot,
    },
    utils::StatusMessage,
    ProcResult, ResultMessage,
};
use actix::{Actor, ActorContext, Context, Handler, Message, Supervised, SystemService};
use crypto::{
    keys::{
        bip39,
        slip10::{self, Chain, Curve, Seed},
    },
    signatures::ed25519,
    utils::rand::fill,
};
use engine::{
    snapshot,
    vault::{BoxProvider, ClientId, DbView, Key, RecordHint, RecordId, VaultId},
};
use std::{
    any,
    collections::{HashMap, HashSet},
    convert::TryFrom,
    path::PathBuf,
};
use stronghold_utils::GuardDebug;
use thiserror::Error as DeriveError;

#[derive(DeriveError, Debug)]
pub enum VaultError {
    #[error("Vault does not exist")]
    NotExisting,

    #[error("Failed to revoke record, vault does not exist")]
    RevokationError,

    #[error("Failed to collect gargabe, vault does not exist")]
    GargabeCollectError,

    #[error("Failed to get list, vault does not exist")]
    ListError,

    #[error("Failed to access Vault")]
    AccessError,
}

/// Message types for [`SecureClientActor`]
pub mod messages {

    use std::time::Duration;

    use futures::io::Write;

    use crate::Location;

    use super::*;

    #[derive(Clone, GuardDebug)]
    pub struct Terminate;

    impl Message for Terminate {
        type Result = ();
    }

    #[derive(Clone, GuardDebug)]
    pub struct ReloadData<T: BoxProvider + Send + Sync + Clone + 'static + Unpin> {
        pub id: ClientId,

        // TODO this could be re-worked for generalized synchronisation facilities
        pub data: Box<(HashMap<VaultId, Key<T>>, DbView<T>, Store)>,

        // this might be obsolete, as we can return direct responses
        pub status: StatusMessage,
    }

    impl<T> Message for ReloadData<T>
    where
        T: BoxProvider + Send + Sync + Clone + 'static + Unpin,
    {
        type Result = ();
    }

    #[derive(Clone, GuardDebug)]
    pub struct CreateVault {
        pub location: Location,
        // pub vault_id: VaultId,
        // pub record_id: RecordId,
    }

    impl Message for CreateVault {
        type Result = ();
    }

    #[derive(Clone, GuardDebug)]
    pub struct WriteToVault {
        // pub vault_id: VaultId,
        // pub record_id: RecordId,
        pub location: Location,

        pub payload: Vec<u8>,
        pub hint: RecordHint,
    }

    impl Message for WriteToVault {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct RevokeData {
        pub vault_id: VaultId,
        pub record_id: RecordId,
    }

    impl Message for RevokeData {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct GarbageCollect {
        pub vault_id: VaultId,
    }

    impl Message for GarbageCollect {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct ListIds {
        pub vault_id: VaultId,
    }

    impl Message for ListIds {
        type Result = Result<Vec<(RecordId, RecordHint)>, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct CheckRecord {
        pub vault_id: VaultId,
        pub record_id: RecordId,
    }

    impl Message for CheckRecord {
        type Result = bool;
    }

    #[derive(Clone, GuardDebug)]
    pub struct ReadSnapshot {
        pub key: snapshot::Key,
        pub file_name: Option<String>,
        pub path: Option<PathBuf>,
        pub client_id: ClientId,
        pub former_client_id: Option<ClientId>,
    }

    impl Message for ReadSnapshot {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct ClearCache;

    impl Message for ClearCache {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct FillSnapshot {
        pub client: Client,
    }

    impl Message for FillSnapshot {
        type Result = ();
    }

    #[derive(Clone, GuardDebug)]
    pub struct CheckVault {
        pub vault_path: Vec<u8>,
    }

    impl Message for CheckVault {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct WriteToStore {
        pub location: Location,
        pub payload: Vec<u8>,
        pub lifetime: Option<Duration>,
    }

    impl Message for WriteToStore {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct ReadFromStore {
        pub location: Location,
    }

    impl Message for ReadFromStore {
        type Result = Result<Vec<u8>, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct DeleteFromStore {
        pub location: Location,
    }

    impl Message for DeleteFromStore {
        type Result = Result<(), anyhow::Error>;
    }
}

pub mod procedures {

    use super::*;

    #[derive(Clone, GuardDebug)]
    pub struct SLIP10Generate {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
        pub size_bytes: usize,
    }

    impl Message for SLIP10Generate {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct SLIP10DeriveFromSeed {
        pub chain: Chain,
        pub seed_vault_id: VaultId,
        pub seed_record_id: RecordId,
        pub key_vault_id: VaultId,
        pub key_record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for SLIP10DeriveFromSeed {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct SLIP10DeriveFromKey {
        pub chain: Chain,
        pub parent_vault_id: VaultId,
        pub parent_record_id: RecordId,
        pub child_vault_id: VaultId,
        pub child_record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for SLIP10DeriveFromKey {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct BIP39Generate {
        pub passphrase: String,
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for BIP39Generate {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct BIP39Recover {
        pub mnemonic: String,
        pub passphrase: String,
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for BIP39Recover {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Ed25519PublicKey {
        pub vault_id: VaultId,
        pub record_id: RecordId,
    }

    impl Message for Ed25519PublicKey {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Ed25519Sign {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub msg: Vec<u8>,
    }

    impl Message for Ed25519Sign {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }
}

#[cfg(test)]
pub mod testing {

    use super::*;

    /// INSECURE MESSAGE
    /// MAY ONLY BE USED IN TESTING CONFIGURATIONS
    ///
    /// Reads data from the vault
    pub struct ReadFromVault {
        vault_id: VaultId,
        record_id: RecordId,
    }
}

/// Functional macro to remove boilerplate code for the implementation
/// of the [`SecureActor`].
/// TODO Make receiver type pass as argument.
macro_rules! impl_handler {
    ($mty:ty, $rty:ty, ($sid:ident,$mid:ident, $ctx:ident), $($body:tt)*) => {
        impl<T> Handler<$mty> for SecureClient<T>
        where
            T :  BoxProvider + Send + Sync + Clone + 'static + Unpin /* UNPIN has been added. see Provider for support. */
        {
            type Result = $rty;
            fn handle(&mut $sid, $mid: $mty, $ctx: &mut Self::Context) -> Self::Result {
                $($body)*
            }
        }
    };

    ($mty:ty, $rty:ty, $($body:tt)*) => {
        impl_handler!($mty, $rty, (self,msg,ctx), $($body)*);
    }
}

impl<P> Actor for SecureClient<P>
where
    P: BoxProvider + Send + Sync + Clone + 'static + Unpin, /* UNPIN has been added. see Provider for support. */
{
    type Context = Context<Self>;
}

/// Make the [`SecureActor'] failure resistant
impl<P> Supervised for SecureClient<P> where
    P: BoxProvider + Send + Sync + Clone + 'static + Unpin /* UNPIN has been added. see Provider for support. */
{
}

impl_handler!(messages::Terminate, (), (self, msg, ctx), {
    ctx.stop();
});

impl_handler!(messages::ClearCache, Result<(), anyhow::Error>, (self, msg, ctx), {
    self.keystore.clear_keys();
    self.db.clear().map_err(|e| anyhow::anyhow!(e))
});

impl_handler!(messages::CreateVault, (), (self, msg, ctx), {
    let (vault_id, _) = self.resolve_location(msg.location);

    let key = self.keystore.create_key(vault_id);
    self.db.init_vault(&key, vault_id); // potentially produces an error
});

impl_handler!(messages::CheckRecord, bool, (self, msg, ctx), {
    return match self.keystore.get_key(msg.vault_id) {
        Some(key) => {
            self.keystore.insert_key(msg.vault_id, key);
            self.db.contains_record(&key, msg.vault_id, msg.record_id)
        }
        None => false,
    };
});

impl_handler!(messages::WriteToVault, Result<(), anyhow::Error>, (self, msg, ctx), {

    let (vault_id, record_id) = self.resolve_location(msg.location);

    return match self.keystore.get_key(vault_id) {
        Some(key) => {
            self.keystore.insert_key(vault_id, key);
            self.db.write(&key, vault_id, record_id, &msg.payload, msg.hint).map_err(|e| anyhow::anyhow!(e))
        }
        None => {
            Err(anyhow::anyhow!(VaultError::NotExisting))
        }
    }
});

impl_handler!(messages::RevokeData, Result<(), anyhow::Error>, (self, msg, ctx), {
    return match self.keystore.get_key(msg.vault_id) {
        Some(key) => {
            self.keystore.insert_key(msg.vault_id, key);
            self.db.revoke_record(&key, msg.vault_id, msg.record_id).map_err(|e| anyhow::anyhow!(e))
        }
        None => {
            Err(anyhow::anyhow!(VaultError::RevokationError))
        }
    }
});

impl_handler!(messages::GarbageCollect, Result<(), anyhow::Error>, (self, msg, ctx), {
    return match self.keystore.get_key(msg.vault_id) {
        Some(key) => {
            self.keystore.insert_key(msg.vault_id, key);
            self.db.garbage_collect_vault(&key, msg.vault_id).map_err(|e| anyhow::anyhow!(e))
        }
        None => {
            Err(anyhow::anyhow!(VaultError::GargabeCollectError))
        }
    }
});

impl_handler!(
    messages::ListIds,
    Result<Vec<(RecordId, RecordHint)>, anyhow::Error>,
    (self, msg, ctx),
    {
        match self.keystore.get_key(msg.vault_id) {
            Some(key) => {
                self.keystore.insert_key(msg.vault_id, key);
                Ok(self.db.list_hints_and_ids(&key, msg.vault_id))
            }
            None => Err(anyhow::anyhow!(VaultError::ListError)),
        }
    }
);

impl_handler!(messages::ReloadData<T>, (), (self, msg, ctx), {
    let (keystore, state, store) = *msg.data;
    let vids = keystore.keys().copied().collect::<HashSet<VaultId>>();
    self.keystore.rebuild_keystore(keystore);
    self.db = state;

    self.clear_cache();
    self.rebuild_cache(self.client_id, vids, store);
});

impl_handler!(messages::ReadSnapshot, Result<(), anyhow::Error>, (self, msg, ctx),  {
    let snapshot_actor = Snapshot::from_registry();

    // call read from snapshot from snapshot actor
    todo!()
});

impl_handler!(messages::CheckVault, Result<(), anyhow::Error>, (self, msg, ctx), {
    let vid = self.derive_vault_id(msg.vault_path);
    self.vault_exist(vid).ok_or(anyhow::anyhow!(VaultError::NotExisting));
    Ok(())

});

impl_handler!(messages::WriteToStore, Result<(), anyhow::Error>, (self, msg, ctx), {
    let (vault_id, _) = self.resolve_location(msg.location);
    self.write_to_store(vault_id.into(), msg.payload, msg.lifetime);

    Ok(())
});

impl_handler!(
    messages::ReadFromStore,
    Result<Vec<u8>, anyhow::Error>,
    (self, msg, ctx),
    {
        let (vault_id, _) = self.resolve_location(msg.location);

        match self.read_from_store(vault_id.into()) {
            Some(data) => Ok(data),
            None => Err(anyhow::anyhow!(VaultError::NotExisting)), // semantically wrong, use store error
        }
    }
);

impl_handler!( messages::DeleteFromStore, Result <(), anyhow::Error>, (self, msg, ctx), {
        let (vault_id, _) = self.resolve_location(msg.location);
        self.store_delete_item(vault_id.into());

        Ok(())
});

// ----
// impl for procedures
// ---

impl_handler!(
procedures::SLIP10Generate, Result<crate::ProcResult, anyhow::Error>, (self, msg, ctx), {

    let key = if !self.keystore.vault_exists(msg.vault_id) {
        let key = self.keystore.create_key(msg.vault_id);
        self.db.init_vault(&key, msg.vault_id)?;
        key
    } else {
        self.keystore.get_key(msg.vault_id).unwrap()
    };

    self.keystore.insert_key(msg.vault_id, key.clone());

    let mut seed = vec![0u8; msg.size_bytes];
    fill(&mut seed).map_err(|e| anyhow::anyhow!(e))?;

    self.db.write(&key, msg.vault_id, msg.record_id,&seed, msg.hint).map_err(|e| anyhow::anyhow!(e));

    Ok(crate::ProcResult::SLIP10Generate(StatusMessage::OK))
});

impl_handler!(procedures::SLIP10DeriveFromSeed, Result<crate::ProcResult, anyhow::Error>, (self, msg, ctx), {
    match self.keystore.get_key(msg.seed_vault_id) {

        Some(seed_key) => {
            self.keystore.insert_key(msg.seed_vault_id, seed_key.clone());
            let dk_key = if !self.keystore.vault_exists(msg.key_vault_id) {
                let key = self.keystore.create_key(msg.key_vault_id);
                self.db.init_vault(&key, msg.key_vault_id).map_err(|e| anyhow::anyhow!(e))?;
                key

            } else {
                self.keystore.get_key(msg.key_vault_id).ok_or(
                    Err::<crate::ProcResult, anyhow::Error>(anyhow::anyhow!(crate::Error::KeyStoreError("".into())))
                ).unwrap()
            };

            self.keystore.insert_key(msg.key_vault_id, dk_key.clone());
            self.db.exec_proc(&seed_key, msg.seed_vault_id, msg.seed_record_id, &dk_key, msg.key_vault_id, msg.key_record_id, msg.hint, |gdata| {
                let dk = Seed::from_bytes(&gdata.borrow())
                    .derive(Curve::Ed25519, &msg.chain).map_err(|e| anyhow::anyhow!(e)).unwrap();

                let data : Vec<u8> = dk.into();

                // TODO send client dk.chain_code()

                Ok(data)

            });
            Ok(ProcResult::SLIP10Derive(ResultMessage::Ok([0u8; 32]))) // should contain dk.chain_code()
        }

        None => {
            Err(anyhow::anyhow!(VaultError::NotExisting))
        }
    }
    // todo!()

});

impl_handler!( procedures::SLIP10DeriveFromKey,Result<crate::ProcResult, anyhow::Error>, (self, msg, ctx),{

    match self.keystore.get_key(msg.parent_vault_id) {
        Some(parent_key) => {
            self.keystore.insert_key(msg.parent_vault_id, parent_key.clone());
            let child_key = if !self.keystore.vault_exists(msg.child_vault_id) {
                let key = self.keystore.create_key(msg.child_vault_id);
                self.db.init_vault(&key, msg.child_vault_id);

                key
            } else {
                // todo
                self.keystore.get_key(msg.child_vault_id).unwrap()
            };

            self.keystore.insert_key(msg.child_vault_id, child_key.clone());

            self.db.exec_proc(&parent_key, msg.parent_vault_id, msg.parent_record_id, &child_key, msg.child_vault_id, msg.child_record_id, msg.hint, |parent | {
                        let parent = slip10::Key::try_from(&*parent.borrow()).unwrap();
                        let dk = parent.derive(&msg.chain).unwrap();

                        let data: Vec<u8> = dk.into();

                        // todo: send client dk.chain_code();


                    Ok(data)
            });

            Ok(ProcResult::SLIP10Derive(ResultMessage::Ok(
                [0u8; 32]
            )))
        }
        None => {
            Err(anyhow::anyhow!(VaultError::AccessError))
        }
    }

});

impl_handler!(procedures::BIP39Generate, Result<crate::ProcResult, anyhow::Error>, (self, msg, ctx), {

            let mut entropy = [0u8; 32];
                fill(&mut entropy).unwrap(); // .expect(line_error!());

                let mnemonic = bip39::wordlist::encode(
                    &entropy,
                    &bip39::wordlist::ENGLISH, // TODO: make this user configurable
                ).unwrap(); //
                // .expect(line_error!());

                let mut seed = [0u8; 64];
                bip39::mnemonic_to_seed(&mnemonic, &msg.passphrase, &mut seed);

                let key = if !self.keystore.vault_exists(msg.vault_id) {
                    let k = self.keystore.create_key(msg.vault_id);
                    self.db.init_vault(&k, msg.vault_id).unwrap(); //.expect(line_error!());

                    k
                } else {
                    self.keystore.get_key(msg.vault_id).unwrap() //.expect(line_error!())
                };

                self.keystore.insert_key(msg.vault_id, key.clone());

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.db
                    .write(&key, msg.vault_id, msg.record_id, &seed, msg.hint).unwrap();
                    // .expect(line_error!());

    Ok(ProcResult::BIP39Generate(ResultMessage::OK))
});

impl_handler!(procedures::BIP39Recover, Result<crate::ProcResult, anyhow::Error>, (self, msg, ctx), {

                    let key = if !self.keystore.vault_exists(msg.vault_id) {
                    let k = self.keystore.create_key(msg.vault_id);
                    self.db.init_vault(&k, msg.vault_id).unwrap(); // .expect(line_error!());

                    k
                } else {
                    self.keystore.get_key(msg.vault_id).unwrap() //.expect(line_error!())
                };

                self.keystore.insert_key(msg.vault_id, key.clone());

                let mut seed = [0u8; 64];
                bip39::mnemonic_to_seed(&msg.mnemonic, &msg.passphrase, &mut seed);

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.db
                    .write(&key, msg.vault_id, msg.record_id, &seed, msg.hint).unwrap();
                    // .expect(line_error!());


    Ok(ProcResult::BIP39Recover(ResultMessage::OK))
});

impl_handler!(procedures::Ed25519PublicKey, Result<crate::ProcResult, anyhow::Error>, (self, msg, ctx), {

             if let Some(key) = self.keystore.get_key(msg.vault_id) {
                    self.keystore.insert_key(msg.vault_id, key.clone());

                    self.db
                        .get_guard(&key, msg.vault_id, msg.record_id, |data| {
                            let raw = data.borrow();
                            let mut raw = (*raw).to_vec();

                            if raw.len() < 32 {
                                // client.try_tell(
                                //     ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                //         ProcResult::Ed25519PublicKey(ResultMessage::Error(
                                //             "Incorrect number of key bytes".into(),
                                //         )),
                                //     )),
                                //     sender.clone(),
                                // );

                                // the client actor will interupt the control flow
                                // but could this be an option to return an error
                                return Err(engine::Error::CryptoError(
                                    crypto::Error::BufferSize {has : raw.len(),needs : 32, name: "data buffer" }));

                            }
                            raw.truncate(32);
                            let mut bs = [0; 32];
                            bs.copy_from_slice(&raw);
                            let sk = ed25519::SecretKey::from_le_bytes(bs).unwrap(); //.expect(line_error!());
                            let pk = sk.public_key();

                            // send to client this result
                            // Ok(ProcResult::Ed25519PublicKey(ResultMessage::Ok(pk.to_compressed_bytes())))
                            Ok(())
                        }).unwrap();
                        // .expect(line_error!());

                        // TODO this must be replaced
                        Ok(ProcResult::Ed25519PublicKey(ResultMessage::Ok([0u8; 32])))

                } else {
                    // client.try_tell(
                    //     ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                    //         ProcResult::Ed25519PublicKey(ResultMessage::Error("Failed to access vault".into())),
                    //     )),
                    //     sender,
                    // )

                    Err(anyhow::anyhow!(VaultError::AccessError))
                }


    // todo!()
});

impl_handler!(procedures::Ed25519Sign, Result <crate::ProcResult, anyhow::Error>, (self, msg, ctx), {
            if let Some(pkey) = self.keystore.get_key(msg.vault_id) {
                    self.keystore.insert_key(msg.vault_id, pkey.clone());

                    self.db
                        .get_guard(&pkey, msg.vault_id, msg.record_id, |data| {
                            let raw = data.borrow();
                            let mut raw = (*raw).to_vec();

                            if raw.len() <= 32 {


                                // client.try_tell(
                                //     ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                //         ProcResult::Ed25519Sign(ResultMessage::Error(
                                //             "incorrect number of key bytes".into(),
                                //         )),
                                //     )),
                                //     sender.clone(),
                                // );


                                return Err(engine::Error::CryptoError(
                                    crypto::Error::BufferSize {has : raw.len(),needs : 32, name: "data buffer" }));
                            }
                            raw.truncate(32);
                            let mut bs = [0; 32];
                            bs.copy_from_slice(&raw);
                            let sk = ed25519::SecretKey::from_le_bytes(bs).unwrap(); //expect(line_error!());

                            let sig = sk.sign(&msg.msg);

                            // client.try_tell(
                            //     ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                            //         ProcResult::Ed25519Sign(ResultMessage::Ok(sig.to_bytes())),
                            //     )),
                            //     sender,
                            // );

                            Ok(())
                        }).unwrap();
                        // .expect(line_error!());

                        // TODO
                        Ok(ProcResult::Ed25519Sign(ResultMessage::Ok([0u8; 64]))) //   must return sig.to_bytes())))
                } else {
                    // client.try_tell(
                    //     ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Ed25519Sign(
                    //         ResultMessage::Error("Failed to access vault".into()),
                    //     ))),
                    //     sender,
                    // )

                    Err(anyhow::anyhow!(VaultError::AccessError))
                }

});

#[cfg(test)]
mod tests {
    // TODO
}
