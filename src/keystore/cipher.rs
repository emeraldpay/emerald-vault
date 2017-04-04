//! Advanced encryption standard (AES) cipher

use std::{error, fmt};
use std::str::FromStr;

/// Default cipher name
pub const DEFAULT_CIPHER_NAME: &'static str = AES256_CTR_CIPHER_NAME;

/// `AES256_CRT` cipher name
pub const AES256_CTR_CIPHER_NAME: &'static str = "aes-128-ctr";

/// Cipher type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    /// AES-CTR (specified in (RFC 3686)[https://tools.ietf.org/html/rfc3686])
    Aes256Ctr,
}

impl Default for Cipher {
    fn default() -> Cipher {
        Cipher::Aes256Ctr
    }
}

impl FromStr for Cipher {
    type Err = CipherParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == AES256_CTR_CIPHER_NAME => Ok(Cipher::Aes256Ctr),
            _ => Err(CipherParserError::UnsupportedCipher(s.to_owned())),
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

/// `Cipher` enum parser errors
#[derive(Debug)]
pub enum CipherParserError {
    /// An unsupported cipher
    UnsupportedCipher(String),
}

impl fmt::Display for CipherParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CipherParserError::UnsupportedCipher(ref str) => {
                write!(f, "Unsupported cipher name: {}", str)
            }
        }
    }
}

impl error::Error for CipherParserError {
    fn description(&self) -> &str {
        "Cipher parser error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cipher, DEFAULT_CIPHER_NAME};
    use std::str::FromStr;

    #[test]
    fn should_decode_default_cipher() {
        assert_eq!(Cipher::from_str(DEFAULT_CIPHER_NAME).unwrap(),
                   Cipher::default());
    }

    #[test]
    fn should_not_decode_unknown_cipher() {
        assert!(Cipher::from_str("unknown").is_err());
    }
}
