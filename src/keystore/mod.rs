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

    /// Derived core length
    pub dk_length: usize,

    /// Key derivation function
    pub kdf: Kdf,

    /// Key derivation function salt
    pub kdf_salt: [u8; KDF_SALT_BYTES],

    /// Cipher type
    pub cipher: Cipher,

    /// Cipher encoded text
    pub cipher_text: Vec<u8>,

    /// Cipher initialization vector
    pub cipher_iv: [u8; CIPHER_IV_BYTES],

    /// Keccak-256 based message authentication code
    pub keccak256_mac: [u8; KECCAK256_BYTES],
}

impl KeyFile {
    /// Creates a new `KeyFile` with specified passphrase at random (`rand::OsRng`)
    ///
    /// # Arguments
    ///
    /// * `passphrase` - password for key derivation function
    ///
    pub fn new(passphrase: &str) -> Result<KeyFile, Error> {
        let mut rng = os_random();

        Self::new_custom(PrivateKey::gen_custom(&mut rng),
                         passphrase,
                         Kdf::default(),
                         &mut rng)
    }

    /// Creates a new `KeyFile` with specified `PrivateKey`, passphrase, key derivation function
    /// and with given custom random generator
    ///
    /// # Arguments
    ///
    /// * `pk` - a private key
    /// * `passphrase` - password for key derivation function
    /// * `kdf` - customized key derivation function
    /// * `rnd` - predefined random number generator
    ///
    pub fn new_custom<R: Rng>(pk: PrivateKey,
                              passphrase: &str,
                              kdf: Kdf,
                              rng: &mut R)
                              -> Result<KeyFile, Error> {
        let mut kf = KeyFile {
            uuid: rng.gen::<Uuid>(),
            kdf: kdf,
            kdf_salt: rng.gen::<[u8; KDF_SALT_BYTES]>(),
            ..Default::default()
        };

        kf.encrypt_key_custom(pk, passphrase, rng);

        Ok(kf)
    }

    /// Decrypt public address from keystore file by a passphrase
    pub fn decrypt_address(&self, passphrase: &str) -> Result<Address, Error> {
        let pk = self.decrypt_key(passphrase)?;
        pk.to_address().map_err(Error::from)
    }

    /// Decrypt private key from keystore file by a passphrase
    pub fn decrypt_key(&self, passphrase: &str) -> Result<PrivateKey, Error> {
        let derived = self.kdf.derive(self.dk_length, &self.kdf_salt, passphrase);

        let mut v = derived[16..32].to_vec();
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
        self.encrypt_key_custom(pk, passphrase, &mut os_random());
    }

    /// Encrypt a new private key for keystore file with a passphrase
    /// and with given custom random generator
    pub fn encrypt_key_custom<R: Rng>(&mut self, pk: PrivateKey, passphrase: &str, rng: &mut R) {
        let derived = self.kdf.derive(self.dk_length, &self.kdf_salt, passphrase);

        rng.fill_bytes(&mut self.cipher_iv);

        self.cipher_text = self.cipher.encrypt(&pk, &derived[0..16], &self.cipher_iv);

        let mut v = derived[16..32].to_vec();
        v.extend_from_slice(&self.cipher_text);

        self.keccak256_mac = keccak256(&v);
    }
}

impl Default for KeyFile {
    fn default() -> Self {
        KeyFile {
            uuid: Uuid::default(),
            dk_length: DEFAULT_DK_LENGTH,
            kdf: Kdf::default(),
            kdf_salt: [0u8; KDF_SALT_BYTES],
            cipher: Cipher::default(),
            cipher_text: vec![],
            cipher_iv: [0u8; CIPHER_IV_BYTES],
            keccak256_mac: [0u8; KECCAK256_BYTES],
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

fn os_random() -> OsRng {
    OsRng::new().expect("Expect OS specific random number generator")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_create_keyfile() {
        let pk = PrivateKey::gen();
        let kdf = Kdf::from((8, 2, 1));
        let kf = KeyFile::new_custom(pk, "1234567890", kdf, &mut rand::thread_rng()).unwrap();

        assert_eq!(kf.kdf, kdf);
        assert_eq!(kf.decrypt_key("1234567890").unwrap(), pk);
    }
}
