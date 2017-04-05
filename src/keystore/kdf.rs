//! Keystore files key derivation function

use super::prf::Prf;
use std::{error, fmt};
use std::str::FromStr;

/// PBKDF2 key derivation function name
pub const PBKDF2_KDF_NAME: &'static str = "pbkdf2";

/// Scrypt key derivation function name
pub const SCRYPT_KDF_NAME: &'static str = "scrypt";

/// Key derivation function
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kdf {
    /// PBKDF2 (specified in (RFC 2898)[https://tools.ietf.org/html/rfc2898])
    Pbkdf2 {
        /// Pseudo-Random Functions (`HMAC-SHA-256` by default)
        prf: Prf,

        /// Number of iterations (`262144` by default)
        c: u32,
    },

    /// Scrypt (specified in (RPC 7914)[https://tools.ietf.org/html/rfc7914])
    Scrypt {
        /// Number of iterations (`262144` by default)
        n: u32,

        /// Block size for the underlying hash (`8` by default)
        r: u32,

        /// Parallelization factor (`1` by default)
        p: u32,
    },
}

impl Default for Kdf {
    fn default() -> Kdf {
        Kdf::Scrypt {
            n: 262144,
            r: 8,
            p: 1,
        }
    }
}

impl From<u32> for Kdf {
    fn from(c: u32) -> Self {
        Kdf::Pbkdf2 {
            prf: Prf::default(),
            c: c,
        }
    }
}

impl From<(u32, u32, u32)> for Kdf {
    fn from(t: (u32, u32, u32)) -> Self {
        Kdf::Scrypt {
            n: t.0,
            r: t.1,
            p: t.2,
        }
    }
}

impl FromStr for Kdf {
    type Err = KdfParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == PBKDF2_KDF_NAME => {
                Ok(Kdf::Pbkdf2 {
                       prf: Prf::default(),
                       c: 0,
                   })
            }
            _ if s == SCRYPT_KDF_NAME => Ok(Kdf::Scrypt { n: 0, r: 0, p: 0 }),
            _ => Err(KdfParserError::UnsupportedKdf(s.to_owned())),
        }
    }
}

impl fmt::Display for Kdf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Kdf::Pbkdf2 { .. } => f.write_str(PBKDF2_KDF_NAME),
            Kdf::Scrypt { .. } => f.write_str(SCRYPT_KDF_NAME),
        }
    }
}

/// `Kdf` enum parser errors
#[derive(Debug)]
pub enum KdfParserError {
    /// An unsupported key derivation function
    UnsupportedKdf(String),
}

impl fmt::Display for KdfParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KdfParserError::UnsupportedKdf(ref str) => {
                write!(f, "Unsupported key derivation function name: {}", str)
            }
        }
    }
}

impl error::Error for KdfParserError {
    fn description(&self) -> &str {
        "Key derivation function parser error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
