//! # Extract private key from keystore file

use super::{Cipher, Error, Kdf, KeyFile};
use super::util::KECCAK256_BYTES;
use crypto::aes::{KeySize, ctr};
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;
use crypto::scrypt::{ScryptParams, scrypt};
use crypto::sha2::Sha256;
use crypto::sha3::{Sha3, Sha3Mode};

/// Private key length in bytes
pub const PRIVATE_KEY_BYTES: usize = 32;

/// Private key type
pub type PrivateKey = [u8; PRIVATE_KEY_BYTES];

impl KeyFile {
    /// Extract keystore file private core by passphrase
    pub fn extract_key(&self, passphrase: &str) -> Result<PrivateKey, Error> {
        let derived = derive_key(self.dk_length, self.kdf, &self.kdf_salt, passphrase);
        let mac = calculate_mac(&derived[16..32], &self.cipher_text);

        if mac != self.keccak256_mac {
            return Err(Error::FailedMacValidation);
        }

        Ok(decrypt_key(self.cipher,
                       &self.cipher_text,
                       &derived[0..16],
                       &self.cipher_iv))
    }

    /// Create keystore file from private core with a passphrase
    pub fn insert_key(&mut self, pk: &[u8], passphrase: &str) {
        let derived = derive_key(self.dk_length, self.kdf, &self.kdf_salt, passphrase);
        let c_text: [u8; 32] = decrypt_key(self.cipher, pk, &derived[0..16], &self.cipher_iv)
            .into();

        self.cipher_text = c_text.to_vec();
        self.keccak256_mac = calculate_mac(&derived[16..32], &self.cipher_text);
    }
}

fn derive_key(len: usize, kdf: Kdf, kdf_salt: &[u8], passphrase: &str) -> Vec<u8> {
    let mut key = vec![0u8; len];

    match kdf {
        Kdf::Pbkdf2 { prf: _prf, c } => {
            let mut hmac = Hmac::new(Sha256::new(), passphrase.as_bytes());
            pbkdf2(&mut hmac, kdf_salt, c, &mut key);
        }
        Kdf::Scrypt { n, r, p } => {
            let log_n = (n as f64).log2().round() as u8;
            let params = ScryptParams::new(log_n, r, p);
            scrypt(passphrase.as_bytes(), kdf_salt, &params, &mut key);
        }
    }

    key
}

fn encrypt_text(_cipher: Cipher, text: &[u8], key: &[u8], iv: &[u8]) -> [u8; 32] {
    let mut key = [0u8; PRIVATE_KEY_BYTES];
    let mut ctr = ctr(KeySize::KeySize128, key, iv);

    ctr.process(text, &mut key);

    PrivateKey::from_slice(&key)
}

fn calculate_mac(key: &[u8], data: &[u8]) -> [u8; KECCAK256_BYTES] {
    let mut mac = [0u8; KECCAK256_BYTES];
    let mut sha3 = Sha3::new(Sha3Mode::Keccak256);

    sha3.input(key);
    sha3.input(data);
    sha3.result(&mut mac);

    mac
}

fn decrypt_key(_cipher: Cipher, text: &[u8], key: &[u8], iv: &[u8]) -> PrivateKey {
    let mut pkey = [0u8; PRIVATE_KEY_BYTES];
    let mut ctr = ctr(KeySize::KeySize128, key, iv);

    ctr.process(text, &mut pkey);

    PrivateKey::from_slice(&pkey)
}

/// Test Vectors from https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
#[cfg(test)]
pub mod tests {
    use super::{calculate_mac, decrypt_key, derive_key};
    use keystore::{Cipher, Kdf, KeyFile};
    use rustc_serialize::hex::{FromHex, ToHex};
    use std::convert::AsMut;

    #[test]
    fn should_derive_key_via_pbkdf2() {
        let kdf_salt = "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
            .from_hex()
            .unwrap();

        assert_eq!(derive_key(32, Kdf::from(262144), &kdf_salt, "testpassword").to_hex(),
                   "f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551");
    }

    #[test]
    fn should_derive_key_via_scrypt() {
        let kdf_salt = "fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4"
            .from_hex()
            .unwrap();

        assert_eq!(derive_key(32, Kdf::from((1024, 8, 1)), &kdf_salt, "1234567890").to_hex(),
                   "b424c7c40d2409b8b7dce0d172bda34ca70e57232eb74db89396b55304dbe273");
    }

    #[test]
    fn should_decrypt_key() {
        let text = "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
            .from_hex()
            .unwrap();
        let key = "f06d69cdc7da0faffb1008270bca38f5".from_hex().unwrap();
        let iv = "6087dab2f9fdbbfaddc31a909735c1e6".from_hex().unwrap();

        let pkey_val: [u8; 32] = decrypt_key(Cipher::Aes256Ctr, &text, &key, &iv).into();

        assert_eq!(pkey_val.to_hex(),
                   "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d");
    }

    #[test]
    fn should_insert_key() {
        let key = "fa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f"
            .from_hex()
            .unwrap();
        let password = "1234567890";

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

        let res = kf.insert_key(&key, &password);
        assert!(res.is_ok());

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

    #[test]
    fn should_calculate_mac() {
        let key = "e31891a3a773950e6d0fea48a7188551".from_hex().unwrap();
        let data = "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
            .from_hex()
            .unwrap();

        assert_eq!(calculate_mac(&key, &data).to_hex(),
                   "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
    }
}
