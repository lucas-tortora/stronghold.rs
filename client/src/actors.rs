// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod client;

#[deprecated]
mod internal;
mod registry;
mod secure;
mod snapshot;

pub use self::{
    client::{ProcResult, Procedure, SHRequest, SHResults, SLIP10DeriveInput},
    internal::{InternalActor, InternalMsg, InternalResults},
    registry::{GetClient, HasClient, InsertClient, Registry, RegistryError, RemoveClient},
    secure::messages,
    secure::SecureActor,
    snapshot::SMsg,
};

#[cfg(feature = "communication")]
pub use self::client::SHRequestPermission;
