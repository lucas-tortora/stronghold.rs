// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Registry Actor
//!
//! The registry actor keeps record of all client actors
//! bound to a unique `client_id`. [`Client`] actors can
//! be added, removed or queried for their [`actix::Addr`].
//! The main purpose is to access client actors
//!
//! # Examples
//! ```no_run
//! // create a registry
//! let registry = Registry::default().start();
//!
//! ```

use actix::{Actor, Addr, Handler, Message, Supervised};
use engine::vault::ClientId;
use std::collections::HashMap;
use thiserror::Error as ErrorType;

use crate::state::client::Client;

// re-exported

#[derive(ErrorType)]
pub enum RegistryError {
    #[error("No Client Present By Id ({0})")]
    NoClientPresentById(String),

    #[error("Client Already Present By Id ({0})")]
    ClientAlreadyPresentById(String),
}

// message types

#[derive(Message)]
#[rtype(return = "()")]
pub struct InsertClient<R>
where
    R: AsRef<ClientId>,
{
    id: R,
}

#[derive(Message)]
#[rtype(return = "()")]
pub struct RemoveClient<R>
where
    R: AsRef<ClientId>,
{
    id: R,
}

#[derive(Message)]
#[rtype(return = "Addr<Client>")]
pub struct GetClient<R>
where
    R: AsRef<ClientId>,
{
    id: R,
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

impl<A> Actor for Registry<A> where A: Actor {}

impl<A, R> Handler<InsertClient<R>> for Registry<A>
where
    A: Actor,
    R: AsRef<ClientId>,
{
    type Result = Result<Addr<A>, RegistryError>;

    fn handle(&mut self, msg: InsertClient<R>, ctx: &mut Self::Context) -> Self::Result {
        if let Some(_) = self.clients.get(msg.id) {
            return Err(RegistryError::ClientAlreadyPresentById(msg.id));
        }

        self.clients
            .insert(msg.id, Client::new(msg.id).start())
            .ok_or(RegistryError::ClientAlreadyPresentById())
    }
}

impl<A, R> Handler<GetClient<R>> for Registry<A> {
    type Result = Option<Addr<A>>;

    fn handle(&mut self, msg: GetClient<R>, ctx: &mut Self::Context) -> Self::Result {
        self.clients.get(msg.id)
    }
}

impl<A, R> Handler<RemoveClient<R>> for Registry<A> {
    type Result = Result<(), RegistryError>;

    fn handle(&mut self, msg: RemoveClient<R>, ctx: &mut Self::Context) -> Self::Result {
        match self.clients.remove(msg.id) {
            Some(_) => Ok(()),
            None => Err(RegistryError::NoClientPresentById(msg.id)),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[actix::test]
    async fn test_insert_client() {
        let registry = Registry::default().start();

        for d in 'a'..'z' {
            assert!(registry
                .send(InsertClient {
                    id: format!("client {}", d).as_str().as_bytes()
                })
                .await
                .is_ok());
        }
    }

    #[actix::test]
    async fn test_get_client() {
        let registry = Registry::default().start();

        for d in 'a'..'z' {
            assert!(registry
                .send(InsertClient {
                    id: format!("client {}", d).as_str().as_bytes()
                })
                .await
                .is_ok());
        }

        assert!(registry
            .send(GetClient {
                id: format!("client {}", 'a').as_str().as_bytes()
            })
            .await
            .is_some());
    }

    #[actix::test]
    async fn test_remove_client() {
        let registry = Registry::default().start();

        for d in 'a'..'z' {
            assert!(registry
                .send(InsertClient {
                    id: format!("client {}", d).as_str().as_bytes()
                })
                .await
                .is_ok());
        }

        assert!(registry
            .send(RemoveClient {
                id: format!("client {}", 'a').as_str().as_bytes()
            })
            .await
            .is_some());
    }
}
