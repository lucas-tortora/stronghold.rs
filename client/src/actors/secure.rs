// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Actor module
//!
//! The secure actor runs as service, isolates contained data, and synchronizes
//! across multiple access.

use actix::{Actor, ArbiterService, Handler, Message, Supervised};

pub struct SecureActor {}

impl Actor for SecureActor {}

impl Supervised for SecureActor {}

impl ArbiterService for SecureActor {}

#[cfg(test)]
mod tests {}
