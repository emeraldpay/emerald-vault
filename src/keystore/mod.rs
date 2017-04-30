//! # Keystore files (UTC / JSON) encrypted with a passphrase module
//!
//! [Web3 Secret Storage Definition](
//! https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition)

mod error;
mod cipher;
mod kdf;
mod prf;
mod serialize;

pub use self::cipher::Cipher;
pub use self::error::Error;
pub use self::kdf::Kdf;
pub use self::prf::Prf;
use super::core::{self, Address, PrivateKey};
use super::util::{self, KECCAK256_BYTES, keccak256, to_arr};
use rand::{OsRng, Rng};
use std::{cmp, fmt};
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
    /// Generate default wallet with unique `uuid`
    pub fn new() -> Self {
        let mut kf = Self::from(Uuid::new_v4());

        let mut rng = OsRng::new().expect("Expect OS specific random number generator");
        rng.fill_bytes(&mut kf.kdf_salt);
        rng.fill_bytes(&mut kf.cipher_iv);

        kf
    }

    /// Creates a new `KeyFile` with specified passphrase
    /// Uses supplied `PrivateKey` or generates new one
    /// `Address` inclusion defined by flag
    ///
    /// # Arguments
    ///
    /// * `passphrase` - password for key derivation function
    /// * `kdf` - customized key derivation function
    /// * `with_addr` - flag for address inclusion
    ///
    pub fn create_custom(passphrase: &str, kdf: Kdf, with_addr: bool) -> Result<KeyFile, Error> {
        let mut kf = KeyFile::new();
        kf.kdf = kdf;

        let pk = PrivateKey::gen();
        if with_addr {
            kf.with_address(&pk.to_address()?);
        }
        kf.encrypt_key(pk, passphrase);

        Ok(kf)
    }

    /// Creates a new `KeyFile` with specified passphrase
    /// `Address` inclusion defined by flag
    ///
    /// # Arguments
    ///
    /// * `passphrase` - password for key derivation function
    /// * `with_addr` - flag for address inclusion
    ///
    pub fn create(passphrase: &str, with_addr: bool) -> Result<KeyFile, Error> {
        let mut kf = KeyFile::new();
        let pk = PrivateKey::gen();

        if with_addr {
            kf.with_address(&pk.to_address()?);
        }
        kf.encrypt_key(pk, passphrase);

        Ok(kf)
    }

    /// Append `Address` to current wallet
    pub fn with_address(&mut self, addr: &Address) {
        self.address = Some(*addr);
    }

    /// Decrypt private key from keystore file by a passphrase
    pub fn decrypt_key(&self, passphrase: &str) -> Result<PrivateKey, Error> {
        let derived = self.kdf
            .derive(self.dk_length, &self.kdf_salt, passphrase);

        let mut v = vec![];
        v.extend_from_slice(&derived[16..32]);
        v.extend_from_slice(&self.cipher_text);

        if keccak256(&v) != self.keccak256_mac {
            return Err(Error::FailedMacValidation);
        }

        Ok(PrivateKey(to_arr(&self.cipher
                                  .encrypt(&self.cipher_text,
                                           &derived[0..16],
                                           &self.cipher_iv))))
    }

    /// Encrypt a new private key for keystore file with a passphrase
    pub fn encrypt_key(&mut self, pk: PrivateKey, passphrase: &str) {
        let derived = self.kdf
            .derive(self.dk_length, &self.kdf_salt, passphrase);

        self.cipher_text = self.cipher
            .encrypt(&pk, &derived[0..16], &self.cipher_iv);

        let mut v = vec![];
        v.extend_from_slice(&derived[16..32]);
        v.extend_from_slice(&self.cipher_text);

        self.keccak256_mac = keccak256(&v);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_eq_regardless_of_address() {
        let key_without_address = KeyFile::new();

        let mut key_with_address = key_without_address.clone();

        key_with_address.with_address(&"0x0e7c045110b8dbf29765047380898919c5cb56f4"
                                           .parse::<Address>()
                                           .unwrap());

        assert_eq!(key_without_address, key_with_address);
    }

    #[test]
    fn should_create() {
        assert!(KeyFile::create("1234567890", false).is_ok());
    }

    #[test]
    fn should_create_custom() {
        let custom_kdf = Kdf::from((8, 2, 1));
        let res = KeyFile::create_custom("1234567890", custom_kdf, false);

        assert!(res.is_ok());
        assert_eq!(custom_kdf, res.unwrap().kdf);
    }
}
