// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Actor module
//!
//! The secure actor runs as service, isolates contained data, and synchronizes
//! across multiple accesses.
//!

// TODO - read from store
// TODO - read from store

use actix::{Actor, ActorContext, Context, Handler, Message, Supervised, SystemService};

/// Message types for [`SecureActor`]
pub mod messages {

    use actix::Message;

    #[derive(Message)]
    #[rtype(return = "()")]
    pub struct Terminate;
}

#[derive(Default)]
pub struct SecureActor {}

impl Actor for SecureActor {
    type Context = Context<Self>;
}
impl Supervised for SecureActor {}
impl SystemService for SecureActor {}

impl Handler<messages::Terminate> for SecureActor {
    type Result = ();

    fn handle(&mut self, msg: messages::Terminate, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop()
    }
}

#[cfg(test)]
mod tests {}
