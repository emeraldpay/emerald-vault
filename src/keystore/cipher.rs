//! # Advanced encryption standard (AES) cipher

use super::Error;
use crypto::aes::{KeySize, ctr};
use std::fmt;
use std::str::FromStr;

/// `AES256_CRT` cipher name
pub const AES256_CTR_CIPHER_NAME: &'static str = "aes-128-ctr";

/// Cipher type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    /// AES-CTR (specified in (RFC 3686)[https://tools.ietf.org/html/rfc3686])
    Aes256Ctr,
}

impl Cipher {
    pub fn process(&self, text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        // TODO: Reimplement with [aessafe](
        // https://github.com/DaGenix/rust-crypto/blob/cc1a5fde1ce957bd1a8a2e30169443cdb4780111/src/aessafe.rs)
        let mut ctr = ctr(KeySize::KeySize128, key, iv);
        let mut buf = Vec::new();
        ctr.process(text, &buf);
        buf
    }
}

impl Default for Cipher {
    fn default() -> Self {
        Cipher::Aes256Ctr
    }
}

impl FromStr for Cipher {
    type Err = KeyFileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == AES256_CTR_CIPHER_NAME => Ok(Cipher::Aes256Ctr),
            _ => Err(KeyFileError::UnsupportedCipher(s.to_string())),
        }
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Cipher::Aes256Ctr => f.write_str(AES256_CTR_CIPHER_NAME),
        }
    }
}
