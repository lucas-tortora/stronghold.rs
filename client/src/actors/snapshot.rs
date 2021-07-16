// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use actix::{Actor, Handler, Message, Supervised, System, SystemService};

use std::path::PathBuf;

use engine::{
    snapshot,
    vault::{ClientId, DbView, Key, VaultId},
};

use stronghold_utils::GuardDebug;

use crate::actors::{secure::messages as secure_messages, SecureActor};
use crate::{
    actors::{InternalMsg, SHResults},
    line_error,
    state::{
        client::Store,
        snapshot::{Snapshot, SnapshotState},
    },
    utils::StatusMessage,
    Provider,
};
pub use messages::*;
use std::collections::HashMap;
use thiserror::Error as DeriveError;

/// Messages used for the Snapshot Actor.
#[derive(Clone, GuardDebug)]
#[deprecated]
pub enum SMsg {
    WriteSnapshot {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
    },
    FillSnapshot {
        data: Box<(HashMap<VaultId, Key<Provider>>, DbView<Provider>, Store)>,
        id: ClientId,
    },
    ReadFromSnapshot {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
        id: ClientId,
        fid: Option<ClientId>,
    },
}

// new actix impl

mod messages {

    use super::*;
    // use actix::Message;

    #[derive(Message)]
    #[rtype(return = "()")]
    pub struct WriteSnapshot {
        pub key: snapshot::Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
    }

    #[derive(Message)]
    #[rtype(return = "()")]
    pub struct FillSnapshot {
        pub data: Box<(HashMap<VaultId, Key<Provider>>, DbView<Provider>, Store)>,
        pub id: ClientId,
    }

    pub struct ReadFromSnapshot {
        pub key: snapshot::Key,
        pub filename: Option<String>,
        pub path: Option<PathBuf>,
        pub id: ClientId,
        pub fid: Option<ClientId>,
    }

    impl Message for ReadFromSnapshot {
        type Result = Result<(), anyhow::Error>;
    }
}

impl Actor for Snapshot {
    type Context = actix::Context<Self>;
}

#[derive(Debug, DeriveError)]
pub enum SnapshotError {
    #[error("Could Not Load Snapshot. Try another password")]
    LoadFailure,
}

// actix impl
impl Supervised for Snapshot {}
impl SystemService for Snapshot {}

impl Handler<messages::FillSnapshot> for Snapshot {
    type Result = ();

    fn handle(&mut self, msg: messages::FillSnapshot, ctx: &mut Self::Context) -> Self::Result {
        self.state.add_data(msg.id, *msg.data);
    }
}

impl Handler<messages::ReadFromSnapshot> for Snapshot {
    type Result = Result<(), anyhow::Error>;

    fn handle(&mut self, msg: messages::ReadFromSnapshot, ctx: &mut Self::Context) -> Self::Result {
        let id_str: String = msg.id.into();
        let cid = msg.fid.unwrap_or(msg.id);

        if self.has_data(cid) {
            let data = self.get_state(cid);

            // load secure actor
            let secure = SecureActor::from_registry();

            secure.send(secure_messages::ReloadData {
                id: cid,
                data: Box::new(data),
                status: StatusMessage::OK,
            });
        } else {
            match Snapshot::read_from_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key) {
                Ok(snapshot) => {
                    let data = snapshot.get_state(cid);
                    *self = snapshot;

                    // load secure actor
                    let secure = SecureActor::from_registry();
                    secure.send(secure_messages::ReloadData {
                        id: cid,
                        data: Box::new(data),
                        status: StatusMessage::OK,
                    });
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(SnapshotError::LoadFailure).into());
                }
            }
        }

        Ok(())
    }
}

impl Handler<messages::WriteSnapshot> for Snapshot {
    type Result = ();

    fn handle(&mut self, msg: messages::WriteSnapshot, ctx: &mut Self::Context) -> Self::Result {
        self.write_to_snapshot(msg.filename.as_deref(), msg.path.as_deref(), msg.key)
            .expect(line_error!());

        self.state = SnapshotState::default();
    }
}

// old impl
// impl Receive<SMsg> for Snapshot {
//     type Msg = SMsg;

//     fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
//         match msg {
//             SMsg::FillSnapshot { data, id } => {
//                 self.state.add_data(id, *data);

//                 sender
//                     .as_ref()
//                     .expect(line_error!())
//                     .try_tell(SHResults::ReturnFillSnap(StatusMessage::OK), None)
//                     .expect(line_error!());
//             }
//             SMsg::ReadFromSnapshot {
//                 key,
//                 filename,
//                 path,
//                 id,
//                 fid,
//             } => {
//                 let id_str: String = id.into();
//                 let internal = ctx.select(&format!("/user/internal-{}/", id_str)).expect(line_error!());
//                 let cid = if let Some(fid) = fid { fid } else { id };

//                 if self.has_data(cid) {
//                     let data = self.get_state(cid);

//                     internal.try_tell(
//                         InternalMsg::ReloadData {
//                             id: cid,
//                             data: Box::new(data),
//                             status: StatusMessage::OK,
//                         },
//                         sender,
//                     );
//                 } else {
//                     match Snapshot::read_from_snapshot(filename.as_deref(), path.as_deref(), key) {
//                         Ok(mut snapshot) => {
//                             let data = snapshot.get_state(cid);

//                             *self = snapshot;

//                             internal.try_tell(
//                                 InternalMsg::ReloadData {
//                                     id: cid,
//                                     data: Box::new(data),
//                                     status: StatusMessage::OK,
//                                 },
//                                 sender,
//                             );
//                         }
//                         Err(e) => {
//                             sender
//                                 .as_ref()
//                                 .expect(line_error!())
//                                 .try_tell(
//                                     SHResults::ReturnReadSnap(StatusMessage::Error(format!(
//                                         "{}, Unable to read snapshot. Please try another password.",
//                                         e
//                                     ))),
//                                     None,
//                                 )
//                                 .expect(line_error!());
//                         }
//                     }
//                 };
//             }
//             SMsg::WriteSnapshot { key, filename, path } => {
//                 self.write_to_snapshot(filename.as_deref(), path.as_deref(), key)
//                     .expect(line_error!());

//                 self.state = SnapshotState::default();

//                 sender
//                     .as_ref()
//                     .expect(line_error!())
//                     .try_tell(SHResults::ReturnWriteSnap(StatusMessage::OK), None)
//                     .expect(line_error!());
//             }
//         }
//     }
// }
