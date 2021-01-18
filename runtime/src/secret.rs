// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use crate::mem::{GuardedBox, GuardedVec, GuardedString};
use core::convert::TryInto;

#[derive(Debug, PartialEq)]
pub enum Error {
    View { reason: &'static str },
}

impl Error {
    fn view(reason: &'static str) -> crate::Error {
        (Error::View { reason }).into()
    }
}

pub trait Protection<'a, A: Protectable<'a>> {
    type AtRest;
    fn protect(&self, a: A) -> crate::Result<Self::AtRest>;
}

pub trait Access<'a, A: Protectable<'a>, P: Protection<'a, A>> {
    fn access<R: AsRef<P::AtRest>>(&self, r: R) -> crate::Result<A::Accessor>;
}

use std::vec::Vec;

pub trait Protectable<'a> {
    fn into_plaintext(self) -> Vec<u8>;

    type Accessor;
    fn view_plaintext(bs: &[u8]) -> crate::Result<Self::Accessor>;
}

impl<'a> Protectable<'a> for u32 {
    fn into_plaintext(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }

    type Accessor = GuardedBox<u32>;
    fn view_plaintext(bs: &[u8]) -> crate::Result<Self::Accessor> {
        if bs.len() == core::mem::size_of::<Self>() {
            GuardedBox::new(Self::from_le_bytes(bs.try_into().unwrap()))
        } else {
            Err(Error::view("can't interpret bytestring as a u32 in little endian"))
        }
    }
}

impl<'a> Protectable<'a> for Vec<u8> {
    fn into_plaintext(self) -> Vec<u8> {
        self
    }

    type Accessor = GuardedVec<u8>;
    fn view_plaintext(bs: &[u8]) -> crate::Result<Self::Accessor> {
        GuardedVec::copy(bs)
    }
}

impl<'a> Protectable<'a> for &str {
    fn into_plaintext(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    type Accessor = GuardedString;
    fn view_plaintext(bs: &[u8]) -> crate::Result<Self::Accessor> {
        GuardedString::new(unsafe { core::str::from_utf8_unchecked(bs) })
    }
}

#[cfg(feature = "stdalloc")]
pub mod X25519XChaCha20Poly1305 {
    use super::*;
    use core::marker::PhantomData;
    use crypto::{blake2b, ciphers::chacha::xchacha20poly1305, rand, x25519};
    use std::vec::Vec;

    #[derive(Debug)]
    pub struct Ciphertext<A> {
        ct: Vec<u8>,
        ephemeral_pk: [u8; x25519::PUBLIC_KEY_LENGTH],
        tag: [u8; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE],
        a: PhantomData<A>,
    }

    impl<A> AsRef<Ciphertext<A>> for Ciphertext<A> {
        fn as_ref(&self) -> &Self {
            &self
        }
    }

    pub struct PublicKey([u8; x25519::PUBLIC_KEY_LENGTH]);

    impl<'a, A: Protectable<'a>> Protection<'a, A> for PublicKey {
        type AtRest = Ciphertext<A>;

        fn protect(&self, a: A) -> crate::Result<Self::AtRest> {
            let (PrivateKey(ephemeral_key), PublicKey(ephemeral_pk)) = keypair()?;

            let shared = x25519::X25519(&ephemeral_key, Some(&self.0));

            let nonce = {
                let mut h = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
                let mut i = ephemeral_pk.to_vec();
                i.extend_from_slice(&self.0);
                blake2b::hash(&i, &mut h);
                h
            };

            let mut tag = [0; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE];

            let pt = a.into_plaintext();
            let mut ct = vec![0; pt.len()];
            xchacha20poly1305::encrypt(&mut ct, &mut tag, &pt, &shared, &nonce, &[])?;

            Ok(Ciphertext {
                ct,
                ephemeral_pk,
                tag,
                a: PhantomData,
            })
        }
    }

    pub struct PrivateKey([u8; x25519::SECRET_KEY_LENGTH]);

    pub fn keypair() -> crate::Result<(PrivateKey, PublicKey)> {
        let mut s = PrivateKey([0; x25519::SECRET_KEY_LENGTH]);
        rand::fill(&mut s.0)?;
        let p = PublicKey(x25519::X25519(&s.0, None));
        Ok((s, p))
    }

    impl<'a, A: Protectable<'a>> Access<'a, A, PublicKey> for PrivateKey {
        fn access<CT: AsRef<Ciphertext<A>>>(&self, ct: CT) -> crate::Result<A::Accessor> {
            let shared = x25519::X25519(&self.0, Some(&ct.as_ref().ephemeral_pk));

            let pk = x25519::X25519(&self.0, None);

            let nonce = {
                let mut h = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
                let mut i = ct.as_ref().ephemeral_pk.to_vec();
                i.extend_from_slice(&pk);
                blake2b::hash(&i, &mut h);
                h
            };

            let mut pt = vec![0; ct.as_ref().ct.len()];
            xchacha20poly1305::decrypt(&mut pt, &ct.as_ref().ct, &shared, &ct.as_ref().tag, &nonce, &[])?;

            A::view_plaintext(&pt)
        }
    }

    #[test]
    fn int() -> crate::Result<()> {
        let (private, public) = X25519XChaCha20Poly1305::keypair()?;
        let ct = public.protect(17)?;
        let gb = private.access(&ct)?;
        assert_eq!(*gb.access(), 17);
        Ok(())
    }

    #[test]
    fn bytestring() -> crate::Result<()> {
        let (private, public) = X25519XChaCha20Poly1305::keypair()?;
        let ct = public.protect(vec![0, 1, 2])?;
        let gv = private.access(&ct)?;
        assert_eq!(*gv.access(), [0, 1, 2]);
        Ok(())
    }

    #[test]
    fn string() -> crate::Result<()> {
        let (private, public) = X25519XChaCha20Poly1305::keypair()?;
        let ct = public.protect("foo")?;
        let gs = private.access(&ct)?;
        assert_eq!(*gs.access(), *"foo");
        Ok(())
    }
}

pub mod AES {
    use super::*;
    use core::marker::PhantomData;
    use crypto::{ciphers::aes::AES_256_GCM, rand};

    #[derive(Debug)]
    pub struct Ciphertext<A> {
        ct: Vec<u8>,
        iv: [u8; AES_256_GCM::IV_LENGTH],
        tag: [u8; AES_256_GCM::TAG_LENGTH],
        a: PhantomData<A>,
    }

    impl<A> AsRef<Ciphertext<A>> for Ciphertext<A> {
        fn as_ref(&self) -> &Self {
            &self
        }
    }

    pub struct Key([u8; AES_256_GCM::KEY_LENGTH]);

    impl Key {
        pub fn new() -> crate::Result<Self> {
            let mut bs = [0; AES_256_GCM::KEY_LENGTH];
            rand::fill(&mut bs)?;
            Ok(Key(bs))
        }
    }

    impl<'a, A: Protectable<'a>> Protection<'a, A> for Key {
        type AtRest = Ciphertext<A>;

        fn protect(&self, a: A) -> crate::Result<Self::AtRest> {
            let mut iv = [0; AES_256_GCM::IV_LENGTH];
            rand::fill(&mut iv)?;

            let mut tag = [0; AES_256_GCM::TAG_LENGTH];

            let pt = a.into_plaintext();
            let mut ct = vec![0; pt.len()];
            AES_256_GCM::encrypt(&self.0, &iv, &[], &pt, &mut ct, &mut tag)?;

            Ok(Ciphertext {
                ct,
                iv,
                tag,
                a: PhantomData,
            })
        }
    }

    impl<'a, A: Protectable<'a>> Access<'a, A, Key> for Key {
        fn access<CT: AsRef<Ciphertext<A>>>(&self, ct: CT) -> crate::Result<A::Accessor> {
            let mut pt = vec![0; ct.as_ref().ct.len()];
            AES_256_GCM::decrypt(
                &self.0,
                &ct.as_ref().iv,
                &[],
                &ct.as_ref().tag,
                &ct.as_ref().ct,
                &mut pt,
            )?;

            A::view_plaintext(&pt)
        }
    }

    #[test]
    fn int() -> crate::Result<()> {
        let key = AES::Key::new()?;
        let ct = key.protect(17)?;
        let gb = key.access(&ct)?;
        assert_eq!(*gb.access(), 17);
        Ok(())
    }

    #[test]
    fn bytestring() -> crate::Result<()> {
        let key = AES::Key::new()?;
        let ct = key.protect(vec![0, 1, 2])?;
        let gv = key.access(&ct)?;
        assert_eq!(*gv.access(), [0, 1, 2]);
        Ok(())
    }

    #[test]
    fn string() -> crate::Result<()> {
        let key = AES::Key::new()?;
        let ct = key.protect("foo")?;
        let gs = key.access(&ct)?;
        assert_eq!(*gs.access(), *"foo");
        Ok(())
    }
}
