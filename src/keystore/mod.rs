//! # Keystore files (UTC / JSON) encrypted with a passphrase
//!
//! (Web3 Secret Storage Definition)
//! [https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition]

pub mod error;
pub mod cipher;
pub mod extract_key;
pub mod kdf;
pub mod prf;
pub mod serialize;
pub mod sign;

pub use self::cipher::Cipher;
pub use self::error::KeyFileError;
pub use self::extract_key::PrivateKey;
pub use self::kdf::Kdf;
pub use self::prf::Prf;
use self::serialize::try_extract_address;
use address::Address;
use std::{cmp, fmt, fs, result};
use std::io::Read;
use std::path::Path;
use uuid::Uuid;

/// Derived key length in bytes (by default)
pub const DEFAULT_DK_LENGTH: usize = 32;

/// Key derivation function salt length in bytes
pub const KDF_SALT_BYTES: usize = 32;

/// Keccak-256 hash length in bytes
pub const KECCAK256_BYTES: usize = 32;

/// Cipher initialization vector length in bytes
pub const CIPHER_IV_BYTES: usize = 16;

/// A keystore file related result
pub type Result<T> = result::Result<T, KeyFileError>;

/// A keystore file (account private key encrypted with a passphrase)
#[derive(Clone, Debug, Eq)]
pub struct KeyFile {
    /// UUID v4
    pub uuid: Uuid,

    /// Public address (optional)
    pub address: Option<Address>,

    /// Derived key length
    pub dk_length: usize,

    /// Key derivation function
    pub kdf: Kdf,

    /// Key derivation function salt
    pub kdf_salt: [u8; KDF_SALT_BYTES],

    /// Keccak-256 based message authentication code
    pub keccak256_mac: [u8; KECCAK256_BYTES],

    /// Cipher type
    pub cipher: Cipher,

    /// Cipher encoded text
    pub cipher_text: Vec<u8>,

    /// Cipher initialization vector
    pub cipher_iv: [u8; CIPHER_IV_BYTES],
}

impl KeyFile {
    fn new() -> Self {
        Self::from(Uuid::new_v4())
    }

    fn with_address(&mut self, addr: &Address) {
        self.address = Some(*addr);
    }
}

impl Default for KeyFile {
    fn default() -> KeyFile {
        KeyFile {
            uuid: Uuid::default(),
            address: None,
            dk_length: DEFAULT_DK_LENGTH,
            kdf: Kdf::default(),
            kdf_salt: [0u8; KDF_SALT_BYTES],
            keccak256_mac: [0u8; KECCAK256_BYTES],
            cipher: Cipher::default(),
            cipher_text: vec![],
            cipher_iv: [0u8; CIPHER_IV_BYTES],
        }
    }
}

impl From<Uuid> for KeyFile {
    fn from(uuid: Uuid) -> Self {
        KeyFile {
            uuid: uuid,
            ..KeyFile::default()
        }
    }
}

impl PartialEq for KeyFile {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}

impl PartialOrd for KeyFile {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyFile {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.uuid.cmp(&other.uuid)
    }
}

impl fmt::Display for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keystore file: {}", self.uuid)
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
mod tests {
    use super::KeyFile;
    use address::Address;

    #[test]
    fn should_eq() {
        let key1 = KeyFile::new();

        let mut key2 = key1.clone();

        key2.with_address(&"0x0e7c045110b8dbf29765047380898919c5cb56f4"
                               .parse::<Address>()
                               .unwrap());

        assert_eq!(key1, key2);
    }
}
