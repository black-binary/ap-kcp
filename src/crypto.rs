use std::{num::NonZeroU32, sync::Arc};

use aead::LessSafeKey;
use ring::{
    aead::{self, Nonce, UnboundKey, NONCE_LEN},
    pbkdf2,
    rand::SecureRandom,
    rand::SystemRandom,
};

use crate::core::KcpIo;

pub trait Crypto: Send + Sync {
    fn encrypt(&self, buf: &mut Vec<u8>);
    fn decrypt(&self, buf: &mut Vec<u8>) -> bool;
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

    async fn recv_packet(&self) -> std::io::Result<Vec<u8>> {
        loop {
            let mut packet = self.io.recv_packet().await?;
            if self.crypto.decrypt(&mut packet) {
                return Ok(packet);
            }
        }
    }
}

pub struct AeadCrypto {
    key: LessSafeKey,
    algorithm: &'static aead::Algorithm,
    random: SystemRandom,
}

impl AeadCrypto {
    pub fn new(key: &[u8], algorithm: &'static aead::Algorithm) -> Self {
        let salt = b"ap-kcp-aead-salt";
        let mut key_bytes = Vec::with_capacity(algorithm.key_len());
        key_bytes.resize(algorithm.key_len(), 0);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(32).unwrap(),
            salt,
            key,
            &mut key_bytes,
        );
        let key = UnboundKey::new(algorithm, &key_bytes).unwrap();
        let key = LessSafeKey::new(key);
        Self {
            key,
            algorithm,
            random: SystemRandom::new(),
        }
    }
}

impl<C: Crypto> Crypto for Arc<C> {
    fn encrypt(&self, buf: &mut Vec<u8>) {
        C::encrypt(self, buf)
    }

    fn decrypt(&self, buf: &mut Vec<u8>) -> bool {
        C::decrypt(self, buf)
    }
}

impl Crypto for AeadCrypto {
    fn encrypt(&self, buf: &mut Vec<u8>) {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.random.fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // | ENCRPYTED | TAG | NONCE |
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), buf)
            .unwrap();

        buf.extend_from_slice(&nonce_bytes);
    }

    fn decrypt(&self, buf: &mut Vec<u8>) -> bool {
        if buf.len() < aead::NONCE_LEN + self.algorithm.tag_len() {
            return false;
        }

        let len = buf.len();
        let mut nonce_bytes = [0u8; aead::NONCE_LEN];
        nonce_bytes.copy_from_slice(&buf[len - aead::NONCE_LEN..]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        buf.truncate(len - aead::NONCE_LEN);

        let len = if let Ok(plaintext) = self.key.open_in_place(nonce, aead::Aad::empty(), buf) {
            plaintext.len()
        } else {
            log::error!("failed to decrypt");
            return false;
        };
        buf.truncate(len);
        true
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
