//! # Advanced encryption standard (AES) cipher

use super::Error;
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
