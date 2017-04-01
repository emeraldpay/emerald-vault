extern crate crypto;

use self::crypto::aes::{KeySize, ctr};
use self::crypto::digest::Digest;
use self::crypto::hmac::Hmac;
use self::crypto::pbkdf2::pbkdf2;
use self::crypto::sha2::Sha256;
use self::crypto::sha3::{Sha3, Sha3Mode};
use keystore::{Kdf, KeyFile};
use rustc_serialize::hex::ToHex;
use std::fmt;

pub type PrivateKey = [u8; 32];
pub type DerivedKey = [u8; 32];
pub type MAC = [u8; 32];

/// Cipher Errors
#[derive(Clone)]
pub enum CipherError {
    /// MAC validation error
    InvalidMAC { exp: MAC, act: MAC },
    /// KD Function is not supported
    UnsupportedKDF,
}

impl fmt::Debug for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CipherError::InvalidMAC { exp, act } => {
                write!(f,
                       "Invalid MAC {{ exp: {}, act: {} }}",
                       exp.to_hex(),
                       act.to_hex())
            }
            CipherError::UnsupportedKDF => write!(f, "Unsupported KDF"),
        }
    }
}

/// Key Decryption of version 3 of the Web3 Secret Storage Definition.
pub struct SS3Decrypt {
    key: Box<KeyFile>,
}

impl SS3Decrypt {
    pub fn new(key: KeyFile) -> SS3Decrypt {
        SS3Decrypt { key: Box::new(key) }
    }

    fn derive_key(&self, password: &String) -> Result<DerivedKey, CipherError> {
        match self.key.kdf {
            Kdf::Pbkdf2 { c } => {
                let mut hmac_f = Hmac::new(Sha256::new(), password.as_bytes());
                let mut derived = [0u8; 32];
                pbkdf2(&mut hmac_f, &self.key.kdf_salt, c, &mut derived);
                Ok(derived)
            }
            _ => Err(CipherError::UnsupportedKDF),
        }
    }


    fn prepare_mac(&self, derived: DerivedKey) -> Result<MAC, CipherError> {
        let mut sha3 = Sha3::new(Sha3Mode::Keccak256);
        let mut mac: MAC = [0u8; 32];
        sha3.input(&derived[16..32]);
        sha3.input(&self.key.cipher_text.as_slice());
        sha3.result(&mut mac);
        Ok(mac)
    }

    /// Extract Private Key using provided password
    pub fn get_pk(&self, password: String) -> Result<PrivateKey, CipherError> {
        let derived = self.derive_key(&password)?;
        let mac = self.prepare_mac(derived)?;

        if mac != self.key.keccak256_mac {
            return Err(CipherError::InvalidMAC {
                           exp: self.key.keccak256_mac,
                           act: mac,
                       });
        }

        let mut cipher = ctr(KeySize::KeySize128, &derived[0..16], &self.key.cipher_iv);
        let mut pkey = [0u8; 32];
        cipher.process(&self.key.cipher_text.as_slice(), &mut pkey);
        Ok(pkey)
    }
}


#[cfg(test)]
pub mod tests {

    use super::SS3Decrypt;
    use super::super::{Kdf, KeyFile};
    use rustc_serialize::hex::{FromHex, ToHex};
    use std::str::FromStr;
    use uuid::Uuid;

    // Test Vectors from https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition

    fn test_vector_1() -> SS3Decrypt {
        let mac = "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
            .from_hex()
            .unwrap();
        let salt = "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
            .from_hex()
            .unwrap();
        let iv = "6087dab2f9fdbbfaddc31a909735c1e6".from_hex().unwrap();

        let key = KeyFile {
            id: Uuid::from_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap(),
            address: None,
            cipher_iv: *array_ref!(iv.as_slice(), 0, 16),
            cipher_text: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
                .from_hex()
                .unwrap(),
            kdf: Kdf::Pbkdf2 { c: 262144 },
            kdf_salt: *array_ref!(salt.as_slice(), 0, 32),
            keccak256_mac: *array_ref!(mac.as_slice(), 0, 32),
            dk_length: 32,
        };
        SS3Decrypt::new(key)
    }


    #[test]
    fn should_derive_key_tv1() {
        let key = test_vector_1();
        assert_eq!(key.derive_key(&"testpassword".to_string()).unwrap(),
                   "f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551"
                       .from_hex()
                       .unwrap()
                       .as_slice())
    }

    #[test]
    fn should_mac_tv1() {
        let key = test_vector_1();
        let derived_key = "f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551"
            .from_hex()
            .unwrap();
        assert_eq!(key.prepare_mac(*array_ref!(derived_key.as_slice(), 0, 32))
                       .unwrap()
                       .to_hex(),
                   "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
    }

    #[test]
    fn should_get_pk_tv1() {
        let key = test_vector_1();
        assert_eq!(key.get_pk("testpassword".to_string()).unwrap(),
                   "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
                       .from_hex()
                       .unwrap()
                       .as_slice());
    }
}
