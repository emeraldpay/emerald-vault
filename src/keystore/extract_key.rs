//! # Extract keystore file private key

use super::{KECCAK256_BYTES, Kdf, KeyFile, KeyFileError, Result};
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
    /// Extract keystore file private key by passphrase
    pub fn extract_key(&self, passphrase: &str) -> Result<PrivateKey> {
        let derived = self.derive_key(passphrase);
        let mac = self.calculate_mac(&derived);

        if mac != self.keccak256_mac {
            return Err(KeyFileError::FailedMacValidation);
        }

        let mut pkey = [0u8; PRIVATE_KEY_BYTES];
        let mut ctr = ctr(KeySize::KeySize128, &derived[0..16], &self.cipher_iv);

        ctr.process(&self.cipher_text, &mut pkey);

        Ok(pkey)
    }

    fn derive_key(&self, passphrase: &str) -> Vec<u8> {
        let mut key = vec![0u8; self.dk_length];

        match self.kdf {
            Kdf::Pbkdf2 { prf: _prf, c } => {
                let mut hmac = Hmac::new(Sha256::new(), passphrase.as_bytes());

                pbkdf2(&mut hmac, &self.kdf_salt, c, &mut key);
            }
            Kdf::Scrypt { n, r, p } => {
                let log_n = (n as f64).log2().round() as u8;
                let params = ScryptParams::new(log_n, r, p);

                scrypt(passphrase.as_bytes(), &self.kdf_salt, &params, &mut key);
            }
        }

        key
    }

    fn calculate_mac(&self, derived_key: &[u8]) -> [u8; KECCAK256_BYTES] {
        let mut mac = [0u8; KECCAK256_BYTES];
        let mut sha3 = Sha3::new(Sha3Mode::Keccak256);

        sha3.input(&derived_key[16..32]);
        sha3.input(&self.cipher_text);
        sha3.result(&mut mac);

        mac
    }
}
