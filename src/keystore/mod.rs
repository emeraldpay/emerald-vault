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
pub use self::serialize::{create_keyfile, search_by_address, to_file, try_extract_address};
pub use super::core::{Address, PrivateKey};
use super::util::{KECCAK256_BYTES, keccak256, to_arr};
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
        Self::from(Uuid::new_v4())
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
    pub fn encrypt_key(&mut self, pk: &[u8], passphrase: &str) {
        let derived = self.kdf
            .derive(self.dk_length, &self.kdf_salt, passphrase);

        self.cipher_text = self.cipher.encrypt(pk, &derived[0..16], &self.cipher_iv);

        let mut v = vec![];
        v.extend_from_slice(&derived[16..32]);
        v.extend_from_slice(&self.cipher_text);

        self.keccak256_mac = keccak256(&v);
    }

    /// Creates seed vectors for `kdf` and `cipher`
    pub fn crypto_seed(&mut self) {
        let mut salt: [u8; KDF_SALT_BYTES] = [0; 32];
        let mut iv: [u8; CIPHER_IV_BYTES] = [0; 16];

        let mut rng = OsRng::new().ok().unwrap();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut iv);

        self.kdf_salt = salt;
        self.cipher_iv = iv;
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
    use rustc_serialize::hex::{FromHex, ToHex};

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
    fn should_derive_key_via_pbkdf2() {
        let kdf_salt = "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
            .from_hex()
            .unwrap();

        assert_eq!(Kdf::from(262144)
                       .derive(32, &kdf_salt, "testpassword")
                       .to_hex(),
                   "f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551");
    }

    #[test]
    fn should_derive_key_via_scrypt() {
        let kdf_salt = "fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4"
            .from_hex()
            .unwrap();

        assert_eq!(Kdf::from((1024, 8, 1))
                       .derive(32, &kdf_salt, "1234567890")
                       .to_hex(),
                   "b424c7c40d2409b8b7dce0d172bda34ca70e57232eb74db89396b55304dbe273");
    }

    #[test]
    fn should_decrypt_key() {
        let text = "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
            .from_hex()
            .unwrap();

        let key = "f06d69cdc7da0faffb1008270bca38f5".from_hex().unwrap();
        let iv = "6087dab2f9fdbbfaddc31a909735c1e6".from_hex().unwrap();

        assert_eq!(Cipher::Aes256Ctr.encrypt(&text, &key, &iv).to_hex(),
                   "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d");
    }

    #[test]
    fn should_encrypt_key() {
        let key = "fa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f"
            .from_hex()
            .unwrap();

        let mut kf = KeyFile::default();

        kf.kdf = Kdf::Scrypt {
            n: 1024,
            r: 8,
            p: 1,
        };

        kf.cipher_iv = to_arr(&"9df1649dd1c50f2153917e3b9e7164e9".from_hex().unwrap());
        kf.kdf_salt = to_arr(&"fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4"
                                  .from_hex()
                                  .unwrap());

        kf.encrypt_key(&key, "1234567890");

        assert_eq!(kf.cipher_text,
                   "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1"
                       .from_hex()
                       .unwrap());

        let mac: [u8; 32] =
            to_arr(&"9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5"
                        .from_hex()
                        .unwrap());

        assert_eq!(kf.keccak256_mac, mac);
    }
}
