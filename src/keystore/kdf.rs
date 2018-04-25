//! # Keystore files key derivation function

use super::prf::Prf;
use super::Error;
use crypto::pbkdf2::pbkdf2;
//TODO: solve `mmap` call on windows for `rust-scrypt`
#[cfg(target_os = "windows")]
use crypto::scrypt::{scrypt, ScryptParams};
#[cfg(all(unix))]
use rust_scrypt::{scrypt, ScryptParams};
use std::fmt;
use std::str::FromStr;

/// PBKDF2 key derivation function name
pub const PBKDF2_KDF_NAME: &str = "pbkdf2";

/// Scrypt key derivation function name
pub const SCRYPT_KDF_NAME: &str = "scrypt";

/// Security level for `Kdf`
#[derive(Clone, Copy, Debug)]
pub enum KdfDepthLevel {
    /// Security level used by default
    Normal = 1024,

    /// Advanced security level
    High = 8096,

    /// Top security level (consumes more CPU time)
    Ultra = 262_144,
}

impl fmt::Display for KdfDepthLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            KdfDepthLevel::Normal => "normal",
            KdfDepthLevel::High => "high",
            KdfDepthLevel::Ultra => "ultra",
        };
        write!(f, "{}", printable)
    }
}

impl FromStr for KdfDepthLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "normal" => Ok(KdfDepthLevel::Normal),
            "high" => Ok(KdfDepthLevel::High),
            "ultra" => Ok(KdfDepthLevel::Ultra),
            v => Err(Error::InvalidKdfDepth(v.to_string())),
        }
    }
}

impl Default for KdfDepthLevel {
    fn default() -> Self {
        KdfDepthLevel::Normal
    }
}

/// Key derivation function
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kdf {
    /// PBKDF2 (not recommended, specified in (RFC 2898)[https://tools.ietf.org/html/rfc2898])
    Pbkdf2 {
        /// Pseudo-Random Functions (`HMAC-SHA-256` by default)
        prf: Prf,

        /// Number of iterations (`262144` by default)
        c: u32,
    },

    /// Scrypt (by default, specified in (RPC 7914)[https://tools.ietf.org/html/rfc7914])
    Scrypt {
        /// Number of iterations (`19201` by default)
        n: u32,

        /// Block size for the underlying hash (`8` by default)
        r: u32,

        /// Parallelization factor (`1` by default)
        p: u32,
    },
}

impl Kdf {
    /// Derive fixed size key for given salt and passphrase
    pub fn derive(&self, len: usize, kdf_salt: &[u8], passphrase: &str) -> Vec<u8> {
        let mut key = vec![0u8; len];

        match *self {
            Kdf::Pbkdf2 { prf, c } => {
                match prf {
                    Prf::HmacSha256 => {
                        let mut hmac = prf.hmac(passphrase);
                        pbkdf2(&mut hmac, kdf_salt, c, &mut key);
                    }
                    Prf::HmacSha512 => {
                        let mut hmac = prf.hmac512(passphrase);
                        pbkdf2(&mut hmac, kdf_salt, c, &mut key);
                    }
                };
            }
            #[cfg(target_os = "windows")]
            Kdf::Scrypt { n, r, p } => {
                let log_n = (n as f64).log2().round() as u8;
                let params = ScryptParams::new(log_n, r, p);
                scrypt(passphrase.as_bytes(), kdf_salt, &params, &mut key);
            }
            #[cfg(all(unix))]
            Kdf::Scrypt { n, r, p } => {
                let params = ScryptParams::new(u64::from(n), r, p);
                scrypt(passphrase.as_bytes(), kdf_salt, &params, &mut key);
            }
        }

        key
    }
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf::Scrypt {
            n: 1024,
            r: 8,
            p: 1,
        }
    }
}

impl From<KdfDepthLevel> for Kdf {
    fn from(sec: KdfDepthLevel) -> Self {
        Kdf::from((sec as u32, 8, 1))
    }
}

impl From<u32> for Kdf {
    fn from(c: u32) -> Self {
        Kdf::Pbkdf2 {
            prf: Prf::default(),
            c,
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
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == PBKDF2_KDF_NAME => Ok(Kdf::Pbkdf2 {
                prf: Prf::default(),
                c: 262_144,
            }),
            _ if s == SCRYPT_KDF_NAME => Ok(Kdf::default()),
            _ => Err(Error::UnsupportedKdf(s.to_string())),
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_derive_key_via_pbkdf2() {
        let kdf_salt =
            to_32bytes("ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd");

        assert_eq!(
            Kdf::from(8).derive(32, &kdf_salt, "testpassword").to_hex(),
            "031dc7e0f4f375f6d6fdab7ad8d71834d844e39a6b62f9fb98d942bab76db0f9"
        );
    }

    #[test]
    fn should_derive_key_via_scrypt() {
        let kdf_salt =
            to_32bytes("fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4");

        assert_eq!(
            Kdf::from((2, 8, 1))
                .derive(32, &kdf_salt, "1234567890")
                .to_hex(),
            "52a5dacfcf80e5111d2c7fbed177113a1b48a882b066a017f2c856086680fac7"
        );
    }
}
