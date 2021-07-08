// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Registry Actor
//!
//! The registry actor keeps record of all client actors
//! bound to a unique `client_id`. [`Client`] actors can
//! be added, removed or queried for their [`actix::Addr`].
//! The main purpose is to access client actors.

// TODO - check, if drop needs to be implemented eg. discard existing client
// actors
// TODO -

use actix::{Actor, Addr, Context, Handler, Message, Supervised};
use engine::vault::ClientId;
use std::collections::HashMap;
use thiserror::Error as ErrorType;

use crate::state::client::Client;

#[derive(Debug, ErrorType)]
pub enum RegistryError {
    #[error("No Client Present By Id ({0})")]
    NoClientPresentById(String),

    #[error("Client Already Present By Id ({0})")]
    ClientAlreadyPresentById(String),
}

pub struct InsertClient {
    id: ClientId,
}

impl Message for InsertClient {
    type Result = Result<Addr<Client>, RegistryError>;
}

pub struct RemoveClient {
    id: ClientId,
}

impl Message for RemoveClient {
    type Result = Result<(), RegistryError>;
}

pub struct GetClient {
    id: ClientId,
}

impl Message for GetClient {
    type Result = Option<Addr<Client>>;
}

#[derive(Message)]
#[rtype(result = "bool")]
pub struct HasClient {
    id: ClientId,
}

/// Registry [`Actor`], that owns [`Client`] actors, and manages seem. The Registry
/// can be modified
#[derive(Default)]
pub struct Registry<A>
where
    A: Actor,
{
    clients: HashMap<ClientId, Addr<A>>,
}

impl<A> Supervised for Registry<A> where A: Actor {}

impl<A> Actor for Registry<A>
where
    A: Actor,
{
    type Context = Context<Self>;
}

impl Handler<HasClient> for Registry<Client> {
    type Result = bool;

    fn handle(&mut self, msg: HasClient, ctx: &mut Self::Context) -> Self::Result {
        self.clients.contains_key(&msg.id)
    }
}

impl Handler<InsertClient> for Registry<Client> {
    type Result = Result<Addr<Client>, RegistryError>;

    fn handle(&mut self, msg: InsertClient, ctx: &mut Self::Context) -> Self::Result {
        if let Some(_) = self.clients.get(&msg.id) {
            return Err(RegistryError::ClientAlreadyPresentById(msg.id.into()));
        }

        self.clients
            .insert(msg.id, Client::new(msg.id).start())
            .ok_or(RegistryError::ClientAlreadyPresentById("".to_string()))
    }
}

impl Handler<GetClient> for Registry<Client> {
    type Result = Option<Addr<Client>>;

    fn handle(&mut self, msg: GetClient, ctx: &mut Self::Context) -> Self::Result {
        if let Some(client) = self.clients.get(&msg.id) {
            return Some(client.clone());
        }
        None
    }
}

impl<A> Handler<RemoveClient> for Registry<A>
where
    A: Actor,
{
    type Result = Result<(), RegistryError>;

    fn handle(&mut self, msg: RemoveClient, ctx: &mut Self::Context) -> Self::Result {
        match self.clients.remove(&msg.id) {
            Some(_) => Ok(()),
            None => Err(RegistryError::NoClientPresentById(msg.id.into())),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[actix::test]
    async fn test_insert_client() {
        let registry = Registry::<Client>::default().start();

        for d in 'a'..'z' {
            let id_str = format!("{}", d).as_str().as_bytes();
            let n = registry
                .send(InsertClient {
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
                .send(InsertClient {
                    id: ClientId::load(id_str).unwrap(),
                })
                .await
                .is_ok());
        }

        assert!(registry
            .send(GetClient {
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
                .send(InsertClient {
                    id: ClientId::load(id_str).unwrap(),
                })
                .await
                .is_ok());
        }

        if let Ok(result) = registry
            .send(RemoveClient {
                id: ClientId::load(b"client_path").unwrap(),
            })
            .await
        {
            assert!(result.is_ok())
        }
    }
}
