use std::{num::NonZeroU32, sync::Arc};

use bytes::{Bytes, BytesMut};
use ring::{
    aead::{self, BoundKey, Nonce, NonceSequence},
    error::Unspecified,
    pbkdf2,
    rand::SecureRandom,
    rand::SystemRandom,
};

use crate::core::KcpIo;

pub trait Crypto: Send + Sync {
    fn encrypt(&self, buf: &mut Vec<u8>);
    fn decrypt(&self, buf: &mut Vec<u8>);
}

pub struct CryptoLayer<IO, C> {
    io: IO,
    crypto: C,
}

impl<IO: KcpIo + Send + Sync, C: Crypto> CryptoLayer<IO, C> {
    pub fn wrap(io: IO, crypto: C) -> Self {
        Self { io, crypto }
    }
}

#[async_trait::async_trait]
impl<IO: KcpIo + Send + Sync, C: Crypto> KcpIo for CryptoLayer<IO, C> {
    async fn send_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        self.crypto.encrypt(buf);
        self.io.send_packet(buf).await
    }

    async fn recv_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        self.io.recv_packet(buf).await?;
        self.crypto.decrypt(buf);
        Ok(())
    }
}

struct OneNonceSequence<'a> {
    nonce_bytes: &'a [u8; aead::NONCE_LEN],
    used: bool,
}

impl<'a> NonceSequence for OneNonceSequence<'a> {
    fn advance(&mut self) -> Result<aead::Nonce, Unspecified> {
        if self.used {
            return Err(Unspecified {});
        }
        self.used = true;
        Ok(Nonce::assume_unique_for_key(self.nonce_bytes.clone()))
    }
}

impl<'a> OneNonceSequence<'a> {
    fn new(nonce_bytes: &'a [u8; aead::NONCE_LEN]) -> Self {
        Self {
            nonce_bytes,
            used: false,
        }
    }
}

pub struct AeadCrypto {
    key_bytes: Bytes,
    algorithm: &'static aead::Algorithm,
    random: SystemRandom,
}

impl AeadCrypto {
    pub fn new(key: &[u8], algorithm: &'static aead::Algorithm) -> Self {
        let salt = b"ap-kcp-aead-salt";
        let mut key_bytes = BytesMut::with_capacity(algorithm.key_len());
        key_bytes.resize(algorithm.key_len(), 0);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(32).unwrap(),
            salt,
            key,
            &mut key_bytes,
        );
        let key_bytes = key_bytes.freeze();
        Self {
            key_bytes,
            algorithm,
            random: SystemRandom::new(),
        }
    }
}

impl<C: Crypto> Crypto for Arc<C> {
    fn encrypt(&self, buf: &mut Vec<u8>) {
        C::encrypt(self, buf)
    }

    fn decrypt(&self, buf: &mut Vec<u8>) {
        C::decrypt(self, buf)
    }
}

impl Crypto for AeadCrypto {
    fn encrypt(&self, buf: &mut Vec<u8>) {
        let unbound_key = aead::UnboundKey::new(&self.algorithm, &self.key_bytes).unwrap();

        let mut nonce = [0u8; aead::NONCE_LEN];
        self.random.fill(&mut nonce).unwrap();
        let nonce_sequence = OneNonceSequence::new(&nonce);

        let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence);
        // | ENCRPYTED | TAG | NONCE |
        sealing_key
            .seal_in_place_append_tag(aead::Aad::empty(), buf)
            .unwrap();

        buf.extend_from_slice(&nonce);
    }

    fn decrypt(&self, buf: &mut Vec<u8>) {
        if buf.len() < aead::NONCE_LEN + self.algorithm.tag_len() {
            buf.clear();
            return;
        }

        let len = buf.len();
        let unbound_key = aead::UnboundKey::new(&self.algorithm, &self.key_bytes).unwrap();
        let mut nonce = [0u8; aead::NONCE_LEN];
        nonce.copy_from_slice(&buf[len - aead::NONCE_LEN..]);

        buf.truncate(len - aead::NONCE_LEN);

        let nonce_sequence = OneNonceSequence::new(&nonce);
        let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_sequence);

        let len = if let Ok(plaintext) = opening_key.open_in_place(aead::Aad::empty(), buf) {
            plaintext.len()
        } else {
            log::error!("failed to decrypt");
            0
        };
        buf.truncate(len);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn aead() {
        let crypto = AeadCrypto::new(b"secret_key!", &aead::AES_256_GCM);
        let mut buf = Vec::new();
        buf.extend_from_slice(b"some plaintext");
        crypto.encrypt(&mut buf);
        println!("{:?}", buf);
        crypto.decrypt(&mut buf);
        println!("{:?}", buf);
        assert_eq!(b"some plaintext", &buf[..]);
    }
}
