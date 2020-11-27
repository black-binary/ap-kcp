use std::{num::NonZeroU32, sync::Arc};

use bytes::{BufMut, Bytes, BytesMut};
use ring::{
    aead::{self, BoundKey, Nonce, NonceSequence},
    error::Unspecified,
    pbkdf2,
    rand::SecureRandom,
    rand::SystemRandom,
};

use crate::core::KcpIo;

pub trait Crypto: Send + Sync {
    fn encrypt(&self, buf: &[u8]) -> Bytes;
    fn decrypt(&self, buf: &mut [u8]) -> usize;
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
    async fn send_packet(&self, buf: &[u8]) -> std::io::Result<()> {
        let ciphertext = self.crypto.encrypt(buf);
        self.io.send_packet(&ciphertext).await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.io.recv_packet(buf).await?;
        let size = self.crypto.decrypt(&mut buf[..len]);
        Ok(size)
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
    fn encrypt(&self, buf: &[u8]) -> Bytes {
        C::encrypt(self, buf)
    }

    fn decrypt(&self, buf: &mut [u8]) -> usize {
        C::decrypt(self, buf)
    }
}

impl Crypto for AeadCrypto {
    fn encrypt(&self, buf: &[u8]) -> Bytes {
        let unbound_key = aead::UnboundKey::new(&self.algorithm, &self.key_bytes).unwrap();

        let mut nonce = [0u8; aead::NONCE_LEN];
        self.random.fill(&mut nonce).unwrap();
        let nonce_sequence = OneNonceSequence::new(&nonce);

        let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence);
        let mut cipertext =
            BytesMut::with_capacity(aead::NONCE_LEN + buf.len() + self.algorithm.tag_len());

        // | ENCRPYTED | TAG | NONCE |
        cipertext.put_slice(buf);

        sealing_key
            .seal_in_place_append_tag(aead::Aad::empty(), &mut cipertext)
            .unwrap();

        cipertext.put_slice(&nonce);
        cipertext.freeze()
    }

    fn decrypt(&self, buf: &mut [u8]) -> usize {
        if buf.len() < aead::NONCE_LEN + self.algorithm.tag_len() {
            return 0;
        }
        let len = buf.len();
        let unbound_key = aead::UnboundKey::new(&self.algorithm, &self.key_bytes).unwrap();
        let mut nonce = [0u8; aead::NONCE_LEN];
        nonce.copy_from_slice(&buf[len - aead::NONCE_LEN..]);

        let nonce_sequence = OneNonceSequence::new(&nonce);
        let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_sequence);
        if let Ok(plaintext) =
            opening_key.open_in_place(aead::Aad::empty(), &mut buf[..len - aead::NONCE_LEN])
        {
            plaintext.len()
        } else {
            log::error!("failed to decrypt aead packet");
            0
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn aead() {
        let crypto = AeadCrypto::new(b"secret_key!", &aead::AES_256_GCM);
        let ciphertext = crypto.encrypt(b"some plaintext");
        println!("{:?}", ciphertext);
        let mut plaintext = BytesMut::new();
        plaintext.extend_from_slice(&ciphertext);
        let len = crypto.decrypt(&mut plaintext);
        assert!(len != 0);
        println!("{:?}", plaintext);
        assert_eq!(b"some plaintext", &plaintext[..len]);

        let mut plaintext = BytesMut::new();
        plaintext.extend_from_slice(&ciphertext);
        plaintext[0] = 0;
        let len = crypto.decrypt(&mut plaintext);
        assert!(len == 0);
    }
}
