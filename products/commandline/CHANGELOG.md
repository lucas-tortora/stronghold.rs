# Changelog

## \[0.1.3]

- - replace actor system riker with actix
- introduced registry actor for clients as service
- introduced snapshot actor as service
- merge `Internal` and `Client`-Actors into `SecureClient`
- api change in interface for test reading secrets out of a vault. minimal impact.
- Bumped due to a bump in iota-stronghold.
- [e8b10eac](https://www.github.com/iotaledger/stronghold.rs/commit/e8b10eac4a914e5d78aae40ab4f1da15ac136ac7) feat: Migrating stronghold from riker actor system implementation to actix. client + internal actor have been merged. Message types are transformed into structs. on 2021-08-23
- - make stronghold interface clonable
  - Bumped due to a bump in iota-stronghold.
  - [681a024e](https://www.github.com/iotaledger/stronghold.rs/commit/681a024e7fd5d6095bbf571d5a3d22fb449b54da) Clonable Stronghold Instance ([#257](https://www.github.com/iotaledger/stronghold.rs/pull/257)) on 2021-09-13
- Update inline Docs and README files to reflect the current state of the project.
  - Bumped due to a bump in iota-stronghold.
  - [fc95c271](https://www.github.com/iotaledger/stronghold.rs/commit/fc95c27128dedf8aa2d366776c22cb9c8e3f158a) add changes. on 2021-07-01
  - [eafca12a](https://www.github.com/iotaledger/stronghold.rs/commit/eafca12ad915166d8039df6ad050bb1c65cbe248) fix changes format. on 2021-07-01
- - Add `actors::secure::StoreError::NotExisting` as proper error type for correct error handling in client.
  - Bumped due to a bump in iota-stronghold.
  - [ad57181e](https://www.github.com/iotaledger/stronghold.rs/commit/ad57181e7c5baa4b6ccb66fb464667c97967db08) fix: inconsistent error message. ([#251](https://www.github.com/iotaledger/stronghold.rs/pull/251)) on 2021-08-26
- \[[PR 254](https://github.com/iotaledger/stronghold.rs/pull/254)]\
  Change key handling in the `SecureClient` to avoid unnecessary cloning of keys.
  Remove obsolete VaultId-HashSet from the `SecureClient`.
  - Bumped due to a bump in iota-stronghold.
  - [9b8d0da1](https://www.github.com/iotaledger/stronghold.rs/commit/9b8d0da150afd7446198672c8f7675547031c060) Fix(client): Avoid Key cloning, remove redundant code ([#254](https://www.github.com/iotaledger/stronghold.rs/pull/254)) on 2021-09-09
- - corrects wrong control flow. `write_to_vault` always returned an error even if the operation was successful.
  - Bumped due to a bump in iota-stronghold.
  - [aea8a9dc](https://www.github.com/iotaledger/stronghold.rs/commit/aea8a9dc8c3fa12e5444c5b4bb3303876e4c1a2f) Fix/wrong cf on write to vault ([#253](https://www.github.com/iotaledger/stronghold.rs/pull/253)) on 2021-08-30

## \[0.1.2]

- Merged Store, Vault and Snapshot into a single crate called Stronghold-Engine.
  Merged utils-derive and communication-macros into a new crate called stronghold-derive
  Export Stronghold-derive through Stronghold-utils.
  - Bumped due to a bump in iota-stronghold.
  - [36c8983](https://www.github.com/iotaledger/stronghold.rs/commit/36c8983eefd594c702a9e8b32bad25354ad127c0) merge derive/macro crates. on 2021-04-21
  - [b7d44f5](https://www.github.com/iotaledger/stronghold.rs/commit/b7d44f530e08be27128f25f46b4bb05cf3da99bd) update config. on 2021-04-21

## \[0.1.1]

- Updated cargo.toml files with the updated crypto.rs revisions and authors.
  Fixed logic in snapshot and providers to use the `try_*` encryption and decryption functions.
  Fixed commandline and stopped it from overwriting snapshots.
  - [64e08fe](https://www.github.com/iotaledger/stronghold.rs/commit/64e08fe39454d2191561783d009b155c91db37c1) add .changes. on 2021-03-19
  - [0758b67](https://www.github.com/iotaledger/stronghold.rs/commit/0758b6734a1e22d491345a6b894acea12ab5b1b7) add .changes. on 2021-03-19
