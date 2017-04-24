//! # Keystore files (UTC / JSON) encrypted with a passphrase module
//!
//! [Web3 Secret Storage Definition](
//! https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition)

mod error;
mod cipher;
mod kdf;
mod prf;
mod serialize;
mod extract_key;

pub use self::cipher::Cipher;
pub use self::error::Error;
pub use self::kdf::Kdf;
pub use self::prf::Prf;
use self::serialize::try_extract_address;
use super::core::{self, Address, PRIVATE_KEY_BYTES, PrivateKey};
use super::util::{self, KECCAK256_BYTES};
use chrono::prelude::*;
use rand::{OsRng, Rng};
use rustc_serialize::json;
use std::{cmp, fmt, fs, result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Derived core length in bytes (by default)
pub const DEFAULT_DK_LENGTH: usize = 32;

/// Key derivation function salt length in bytes
pub const KDF_SALT_BYTES: usize = 32;

/// Cipher initialization vector length in bytes
pub const CIPHER_IV_BYTES: usize = 16;

/// A keystore file (account private core encrypted with a passphrase)
#[derive(Clone, Debug, Eq)]
pub struct KeyFile {
    /// UUID v4
    pub uuid: Uuid,

    /// Public address (optional)
    pub address: Option<Address>,

    /// Derived core length
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
    /// Generate a wallet with unique `uuid`
    pub fn new() -> Self {
        Self::from(Uuid::new_v4())
    }

    /// Append `Address` to current wallet
    pub fn with_address(&mut self, addr: &Address) {
        self.address = Some(*addr);
    }
}

impl Default for KeyFile {
    fn default() -> Self {
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
            ..Default::default()
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

/// Search of `KeyFile` by specified `Address`
///
/// # Arguments
///
/// * `path` - path with keystore files
/// * `addr` - target address
///
pub fn search_by_address<P: AsRef<Path>>(path: P, addr: &Address) -> Option<KeyFile> {
    let entries = fs::read_dir(path).expect("Expect to read a keystore directory content");

    for entry in entries {
        let path = entry.expect("Expect keystore directory entry").path();

        if path.is_dir() {
            continue;
        }

        let mut file = fs::File::open(path).expect("Expect to open a keystore file");
        let mut content = String::new();

        if file.read_to_string(&mut content).is_err() {
            continue;
        }

        match try_extract_address(&content) {
            Some(a) if a == *addr => {
                return Some(json::decode::<KeyFile>(&content).expect("Expect to decode keystore \
                                                                      file"));
            }
            _ => continue,
        }
    }

    None
}
/// Creates a new `KeyFile` with a specified `Address`
///
/// # Arguments
///
/// * `pk` - private core for inserting in a `KeyFile`
/// * `passphrase` - password for encryption of private core
/// * `addr` - optional address to be included in `KeyFile`
///
pub fn create_keyfile(pk: PrivateKey,
                      passphrase: &str,
                      addr: Option<Address>)
                      -> Result<KeyFile, Error> {
    let mut kf = KeyFile::default();

    match addr {
        Some(a) => kf.with_address(&a),
        _ => {}
    }

    let mut salt: [u8; KDF_SALT_BYTES] = [0; 32];
    let mut iv: [u8; CIPHER_IV_BYTES] = [0; 16];

    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    kf.kdf_salt = salt;
    kf.cipher_iv = iv;

    kf.insert_key(&pk, passphrase);

    Ok(kf)
}

/// Serializes KeyFile into JSON file with name `UTC-<timestamp>Z--<uuid>`
///
/// # Arguments
///
/// * `kf` - `KeyFile`
/// * `dir` - path to destination directory
///
pub fn to_file(kf: KeyFile, dir: Option<&Path>) -> Result<File, Error> {
    let mut name: String = "UTC-".to_string();
    name.push_str(&get_timestamp());
    name.push_str("--");
    name.push_str(&Uuid::new_v4().to_string());

    let mut p: PathBuf = PathBuf::new();
    let path = match dir {
        Some(dir) => {
            p = PathBuf::from(dir).with_file_name(name);
            p.as_path()
        }
        None => Path::new(&name),
    };

    let mut file = File::create(&path).expect("Expect to create file for KeyFile");
    let data = json::encode(&kf).expect("Expect to encode KeyFile");
    file.write_all(data.as_ref());

    Ok(file)
}

/// Time stamp for core file in format `<timestamp>Z`
pub fn get_timestamp() -> String {
    let mut stamp = UTC::now().to_rfc3339();
    stamp.push_str("Z");

    stamp
}


#[cfg(test)]
mod tests {
    pub use super::*;
    pub use super::tests::*;

    #[test]
    fn should_eq_regardless_of_address() {
        let key_without_address = KeyFile::new();

        let mut key_with_address = key_without_address.clone();

        key_with_address.with_address(&"0x0e7c045110b8dbf29765047380898919c5cb56f4"
                                           .parse::<Address>()
                                           .unwrap());

        assert_eq!(key_without_address, key_with_address);
    }
}
