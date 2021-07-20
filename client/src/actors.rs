// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// #[deprecated]
mod client;

#[deprecated]
mod internal;

mod registry;
mod secure;
mod snapshot;

pub use self::{
    client::{ProcResult, Procedure, SHRequest, SHResults, SLIP10DeriveInput},
    internal::{InternalActor, InternalMsg, InternalResults},
    registry::{
        messages::{GetClient, HasClient, InsertClient, RemoveClient},
        Registry, RegistryError,
    },
    secure::messages as secure_messages,
    secure::procedures as secure_procedures,
    secure::SecureClient,
    snapshot::SMsg,
};

#[cfg(feature = "communication")]
pub use self::client::SHRequestPermission;
