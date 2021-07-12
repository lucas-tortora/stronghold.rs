// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Actor module
//!
//! The secure actor runs as service, isolates contained data, and synchronizes
//! across multiple accesses.
//!

use crate::{
    internals::Provider,
    state::{
        client::{Client, Store},
        key_store::KeyStore,
        snapshot::Snapshot,
    },
    utils::StatusMessage,
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
}

/// Message types for [`SecureActor`]
pub mod messages {

    use super::*;

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct Terminate;

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct ReloadData {
        pub id: ClientId,

        // TODO this could be re-worked for generalized synchronisation facilities
        pub data: Box<(HashMap<VaultId, Key<Provider>>, DbView<Provider>, Store)>,

        // this might be obsolete, as we can return direct responses
        pub status: StatusMessage,
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct CreateVault {
        pub vauld_id: VaultId,
        pub record_id: RecordId,
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct WriteToVault {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub payload: Vec<u8>,
        pub hint: RecordHint,
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
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct CheckRecord {
        pub vault_id: VaultId,
        pub record_id: RecordId,
    }

    impl Message for CheckRecord {
        type Result = bool;
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct ReadSnapshot {
        pub key: snapshot::Key,
        pub file_name: Option<String>,
        pub path: Option<PathBuf>,
        pub client_id: ClientId,
        pub former_client_id: Option<ClientId>,
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct ClearCache;

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct KillInternal;

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct FillSnapshot {
        pub client: Client,
    }
}

pub mod procedures {

    use super::*;

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct SLIP10Generate {
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
        size_bytes: usize,
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct SLIP10DeriveFromSeed {
        chain: Chain,
        seed_vault_id: VaultId,
        seed_record_id: RecordId,
        key_vault_id: VaultId,
        key_record_id: RecordId,
        hint: RecordHint,
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct SLIP10DeriveFromKey {
        chain: Chain,
        parent_vault_id: VaultId,
        parent_record_id: RecordId,
        child_vault_id: VaultId,
        child_record_id: RecordId,
        hint: RecordHint,
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct BIP39Generate {
        passphrase: String,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct BIP39Recover {
        mnemonic: String,
        passphrase: String,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct Ed25519PublicKey {
        vault_id: VaultId,
        record_id: RecordId,
    }

    #[derive(Message, Clone, GuardDebug)]
    #[rtype(return = "()")]
    pub struct Ed25519Sign {
        vault_id: VaultId,
        record_id: RecordId,
        msg: Vec<u8>,
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

macro_rules! impl_handler {
    ($mty:ty, $rty:ty, ($sid:ident,$mid:ident, $ctx:ident), $($body:tt)*) => {
        impl<T> Handler<$mty> for SecureActor<T>
        where
            T :  BoxProvider + Send + Sync + Clone + 'static
        {
            type Result = $rty;
            fn handle(&mut $sid, $mid: $mty, $ctx: &mut Self::Context) -> Self::Result {
                $($body)*
            }
        }
    };

    ($mty:ty, $rty:ty, $($body:tt)*) => {
        impl_handler!($mty, $rty, (self,msg, ctx), $($body)*);
    }
}

#[derive(Default)]
pub struct SecureActor<P>
where
    P: BoxProvider + Send + Sync + Clone + 'static,
{
    client_id: ClientId,
    keystore: KeyStore<P>,
    db: DbView<P>,
}

impl<P> Actor for SecureActor<P>
where
    P: BoxProvider + Send + Sync + Clone + 'static,
{
    type Context = Context<Self>;
}
impl<P> Supervised for SecureActor<P> where P: BoxProvider + Send + Sync + Clone + 'static {}
impl<P> SystemService for SecureActor<P> where P: BoxProvider + Send + Sync + Clone + 'static {}

// implementations

impl_handler!(messages::KillInternal, (), (self, msg, ctx), ctx.stop());
impl_handler!(messages::ClearCache, Result<(), anyhow::Error>, (self, msg, ctx), {
    self.keystore.clear_keys();
    self.db.clear().map_err(|e| anyhow::anyhow!(e))
});

impl_handler!(messages::CreateVault, (), (self, msg, ctx), {
    let key = self.keystore.create_key(msg.id);
    self.db.init_vault(key, msg.vauld_id); // potentially produces an error
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
    return match self.keystore.get_key(msg.vault_id) {
        Some(key) => {
            self.keystore.insert_key(msg.vault_id, key);
            self.db.write(&key, msg.vault_id, msg.record_id, msg.payload, msg.hint).map_err(|e| anyhow::anyhow!(e))
        }
        None => {
            anyhow::anyhow!(VaultError::NotExisting)
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
            anyhow::anyhow!(VaultError::RevokationError)
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
            anyhow::anyhow!(VaultError::GargabeCollectError)
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
            None => {
                anyhow::anyhow!(VaultError::ListError)
            }
        }
    }
);

impl_handler!(messages::ReloadData, (), (self, msg, ctx), {
    let (keystore, state, store) = *msg.data;
    let vids = keystore.keys().copied().collect::<HashSet<VaultId>>();
    self.keystore.rebuild_keystore(keystore);
    self.db = state;

    // call rebuild cache from client actor
    todo!()
});

impl_handler!(messages::ReadSnapshot, Result<(), anyhow::Error>, (self, msg, ctx),  {
    let snapshot_actor = Snapshot::from_registry();

    // call read from snapshot from snapshot actor
    todo!()
});

impl_handler!(messages::ClearCache, Result<(), anyhow::Error>, (self, msg, ctx), {
    self.keystore.clear_keys();
    self.db.clear().map_err(|e| anyhow::anyhow!(e))?;

    Ok(())
});

// impl for procedures



#[cfg(test)]
mod tests {}
