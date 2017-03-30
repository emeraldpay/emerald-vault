//! Keystore files (UTC / JSON) encrypted with a passphrase (Web3 Secret Storage)
//!
//! (Web3 Secret Storage Definition)
//! [https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition]

mod serialize;

use self::serialize::try_extract_address;
use address::Address;
use std::{cmp, fmt, fs};
use std::io::Read;
use std::path::Path;
use uuid::Uuid;

/// Derived key length in bytes (by default)
pub const DEFAULT_DK_LENGTH: u32 = 32;

/// Key derivation function salt length in bytes
pub const KDF_SALT_BYTES: usize = 32;

/// Keccak-256 hash length in bytes
pub const KECCAK256_BYTES: usize = 32;

/// Cipher initialization vector length in bytes
pub const CIPHER_IV_BYTES: usize = 16;

/// A keystore file (account private key encrypted with a passphrase)
#[derive(Clone, Debug, Eq)]
pub struct KeyFile {
    pub id: Uuid,
    pub address: Option<Address>,
    pub dk_length: u32,
    pub kdf: Kdf,
    pub kdf_salt: [u8; KDF_SALT_BYTES],
    pub keccak256_mac: [u8; KECCAK256_BYTES],
    pub cipher_text: Vec<u8>,
    pub cipher_iv: [u8; CIPHER_IV_BYTES],
}

/// Key derivation function
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kdf {
    /// PBKDF2 (specified in (RFC 2898)[https://tools.ietf.org/html/rfc2898])
    #[allow(dead_code)]
    Pbkdf2(u32),

    /// Scrypt (specified in (RPC 7914)[https://tools.ietf.org/html/rfc7914])
    Scrypt(u32, u32, u32),
}

impl KeyFile {
    #[allow(dead_code)]
    fn new() -> Self {
        Self::from(Uuid::new_v4())
    }

    fn with_address(&mut self, addr: &Address) {
        self.address = Some(*addr);
    }
}

impl From<Uuid> for KeyFile {
    fn from(id: Uuid) -> Self {
        KeyFile {
            id: id,
            address: None,
            dk_length: DEFAULT_DK_LENGTH,
            kdf: Kdf::Scrypt(262144, 8, 1),
            kdf_salt: [0; KDF_SALT_BYTES],
            keccak256_mac: [0; KECCAK256_BYTES],
            cipher_text: vec![],
            cipher_iv: [0; CIPHER_IV_BYTES],
        }
    }
}

impl PartialEq for KeyFile {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl PartialOrd for KeyFile {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyFile {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl fmt::Display for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keystore file: {}", self.id)
    }
}

/// If we have specified address in out keystore return `true`, `false` otherwise
pub fn address_exists<P: AsRef<Path>>(path: P, addr: &Address) -> bool {
    let entries = fs::read_dir(path).expect("Expect to read a keystore directory content");

    for entry in entries {
        let path = entry.expect("Expect keystore directory entry").path();

        if path.is_dir() {
            continue;
        }

        let mut file = fs::File::open(path).expect("Expect to open a keystore file");
        let mut text = String::new();

        if file.read_to_string(&mut text).is_err() {
            continue;
        }

        match try_extract_address(&text) {
            Some(a) if a == *addr => return true,
            _ => continue,
        }
    }

    false
}

#[cfg(test)]
mod tests {}
