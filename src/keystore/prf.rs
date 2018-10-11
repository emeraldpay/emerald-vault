//! # Keystore files pseudo-random functions

use super::Error;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use std::fmt;
use std::str::FromStr;

/// `HMAC_SHA256` pseudo-random function name
pub const HMAC_SHA256_PRF_NAME: &str = "hmac-sha256";

/// `HMAC_SHA512` pseudo-random function name
pub const HMAC_SHA512_PRF_NAME: &str = "hmac-sha512";

/// Pseudo-Random Functions (PRFs)
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prf {
    /// HMAC-SHA-256 (specified in (RFC 4868)[https://tools.ietf.org/html/rfc4868])
    #[serde(rename = "hmac-sha256")]
    HmacSha256,

    /// HMAC-SHA-512 (specified in (RFC 4868)[https://tools.ietf.org/html/rfc4868])
    #[serde(rename = "hmac-sha512")]
    HmacSha512,
}

impl Prf {
    /// Calculate hashed message authentication code using SHA-256 digest
    pub fn hmac(&self, passphrase: &str) -> Hmac<Sha256> {
        Hmac::new_varkey(passphrase.as_bytes()).expect("HMAC accepts all key sizes")
    }

    /// Calculate hashed message authentication code using SHA-512 digest
    pub fn hmac512(&self, passphrase: &str) -> Hmac<Sha512> {
        Hmac::new_varkey(passphrase.as_bytes()).expect("HMAC accepts all key sizes")
    }
}

impl Default for Prf {
    fn default() -> Self {
        Prf::HmacSha256
    }
}

impl FromStr for Prf {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == HMAC_SHA256_PRF_NAME => Ok(Prf::HmacSha256),
            _ if s == HMAC_SHA512_PRF_NAME => Ok(Prf::HmacSha512),
            _ => Err(Error::UnsupportedPrf(s.to_string())),
        }
    }
}

impl fmt::Display for Prf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Prf::HmacSha256 => f.write_str(HMAC_SHA256_PRF_NAME),
            Prf::HmacSha512 => f.write_str(HMAC_SHA512_PRF_NAME),
        }
    }
}
