//! # Advanced encryption standard (AES) cipher

use super::Error;
use crypto::aes::{ctr, KeySize};
use std::fmt;
use std::str::FromStr;

/// `AES128_CRT` cipher name
pub const AES128_CTR_CIPHER_NAME: &str = "aes-128-ctr";

/// Cipher type
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    /// AES-CTR (specified in (RFC 3686)[https://tools.ietf.org/html/rfc3686])
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
}

impl Cipher {
    /// Encrypt given text with provided key and initial vector
    pub fn encrypt(&self, data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; data.len()];
        let mut ctr = ctr(KeySize::KeySize128, key, iv);
        ctr.process(data, buf.as_mut_slice());
        buf
    }
}

impl Default for Cipher {
    fn default() -> Self {
        Cipher::Aes128Ctr
    }
}

impl FromStr for Cipher {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == AES128_CTR_CIPHER_NAME => Ok(Cipher::Aes128Ctr),
            _ => Err(Error::UnsupportedCipher(s.to_string())),
        }
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Cipher::Aes128Ctr => f.write_str(AES128_CTR_CIPHER_NAME),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_encrypt_with_aes_ctr() {
        let data = to_16bytes("6bc1bee22e409f96e93d7e117393172a");
        let key = to_16bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = to_16bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        assert_eq!(
            Cipher::Aes128Ctr.encrypt(&data, &key, &iv),
            Vec::from_hex("874d6191b620e3261bef6864990db6ce").unwrap()
        );
    }
}
