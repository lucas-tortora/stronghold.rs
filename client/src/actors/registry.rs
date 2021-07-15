// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Registry Actor
//!
//! The registry actor keeps record of all client actors
//! bound to a unique `client_id`. [`Client`] actors can
//! be added, removed or queried for their [`actix::Addr`].
//! The registry can also be queried for the snapshot actor.

// TODO - check, if drop needs to be implemented eg. discard existing client actors
// TODO - use `impl_handler!` macro from crate::actors::secure::impl_handler! for code consistency
// TODO - decide between generalization, or direct use of clients (actors) and snapshot actor

use actix::{Actor, Addr, Context, Handler, Message, Supervised, SystemService, WeakAddr};
use engine::vault::ClientId;
use std::collections::HashMap;
use thiserror::Error as ErrorType;

use crate::state::{client::Client, snapshot::Snapshot};

#[derive(Debug, ErrorType)]
pub enum RegistryError {
    #[error("No Client Present By Id ({0})")]
    NoClientPresentById(String),

    #[error("Client Already Present By Id ({0})")]
    ClientAlreadyPresentById(String),
}

pub mod messages {

    use super::*;

    pub struct InsertClient {
        pub id: ClientId,
    }

    impl Message for InsertClient {
        type Result = Result<Addr<Client>, RegistryError>;
    }

    pub struct RemoveClient {
        pub id: ClientId,
    }

    impl Message for RemoveClient {
        type Result = Result<(), RegistryError>;
    }

    pub struct GetClient {
        pub id: ClientId,
    }

    impl Message for GetClient {
        type Result = Option<Addr<Client>>;
    }

    #[derive(Message)]
    #[rtype(result = "bool")]
    pub struct HasClient {
        pub id: ClientId,
    }

    pub struct GetSnapshot {
        pub id: ClientId,
    }

    impl Message for GetSnapshot {
        type Result = Option<WeakAddr<Snapshot>>;
    }
}

/// Registry [`Actor`], that owns [`Client`] actors, and manages them. The registry
/// can be modified
#[derive(Default)]
pub struct Registry {
    clients: HashMap<ClientId, Addr<Client>>,
    snapshot: Option<WeakAddr<Snapshot>>,
}

impl Supervised for Registry {
    // TODO check, if certains functions need to be overidden
}

impl Actor for Registry {
    type Context = Context<Self>;
    // TODO check, if certain functions need to be overidden
}

/// For synchronized access across multiple clients, the [`Registry`]
/// will run as a service.
impl SystemService for Registry {}

impl Handler<messages::HasClient> for Registry {
    type Result = bool;

    fn handle(&mut self, msg: messages::HasClient, ctx: &mut Self::Context) -> Self::Result {
        self.clients.contains_key(&msg.id)
    }
}

impl Handler<messages::InsertClient> for Registry {
    type Result = Result<Addr<Client>, RegistryError>;

    fn handle(&mut self, msg: messages::InsertClient, ctx: &mut Self::Context) -> Self::Result {
        if let Some(_) = self.clients.get(&msg.id) {
            return Err(RegistryError::ClientAlreadyPresentById(msg.id.into()));
        }

        self.clients
            .insert(msg.id, Client::new(msg.id).start())
            .ok_or(RegistryError::ClientAlreadyPresentById("".to_string()))
    }
}

impl Handler<messages::GetClient> for Registry {
    type Result = Option<Addr<Client>>;

    fn handle(&mut self, msg: messages::GetClient, ctx: &mut Self::Context) -> Self::Result {
        if let Some(client) = self.clients.get(&msg.id) {
            return Some(client.clone());
        }
        None
    }
}

impl Handler<messages::RemoveClient> for Registry {
    type Result = Result<(), RegistryError>;

    fn handle(&mut self, msg: messages::RemoveClient, ctx: &mut Self::Context) -> Self::Result {
        match self.clients.remove(&msg.id) {
            Some(_) => Ok(()),
            None => Err(RegistryError::NoClientPresentById(msg.id.into())),
        }
    }
}

impl Handler<messages::GetSnapshot> for Registry {
    type Result = Option<WeakAddr<Snapshot>>;

    fn handle(&mut self, msg: messages::GetSnapshot, ctx: &mut Self::Context) -> Self::Result {
        self.snapshot
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[actix::test]
    async fn test_insert_client() {
        let registry = Registry::default().start();

        for d in 'a'..'z' {
            let id_str = format!("{}", d).as_str().as_bytes();
            let n = registry
                .send(messages::InsertClient {
                    id: ClientId::load(id_str).unwrap(),
                })
                .await;

            assert!(n.is_ok());
        }
    }

    #[actix::test]
    async fn test_get_client() {
        let registry = Registry::default().start();

        for d in 'a'..'z' {
            let id_str = format!("{}", d).as_str().as_bytes();
            assert!(registry
                .send(messages::InsertClient {
                    id: ClientId::load(id_str).unwrap(),
                })
                .await
                .is_ok());
        }

        assert!(registry
            .send(messages::GetClient {
                id: ClientId::load(b"client_path").unwrap(),
            })
            .await
            .is_ok());
    }

    #[actix::test]
    async fn test_remove_client() {
        let registry = Registry::default().start();

        for d in 'a'..'z' {
            let id_str = format!("{}", d).as_str().as_bytes();
            assert!(registry
                .send(messages::InsertClient {
                    id: ClientId::load(id_str).unwrap(),
                })
                .await
                .is_ok());
        }

        if let Ok(result) = registry
            .send(messages::RemoveClient {
                id: ClientId::load(b"client_path").unwrap(),
            })
            .await
        {
            assert!(result.is_ok())
        }
    }
}
