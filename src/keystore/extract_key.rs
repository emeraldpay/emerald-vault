//! Extract private keys from keystore files

use crypto::aes::{KeySize, ctr};
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;
use crypto::scrypt::{ScryptParams, scrypt};
use crypto::sha2::Sha256;
use crypto::sha3::{Sha3, Sha3Mode};
use keystore::{Kdf, KeyFile};
use rustc_serialize::hex::ToHex;
use std::fmt;

pub trait ExtractKey {
    /// Extract private key using provided password
    fn get_pk(&self, password: String) -> Result<PrivateKey, CipherError>;
}

pub type PrivateKey = [u8; 32];
pub type DerivedKey = [u8; 32];
pub type MAC = [u8; 32];

/// Cipher Errors
#[derive(Clone)]
pub enum CipherError {
    /// MAC validation error
    InvalidMAC { exp: MAC, act: MAC },
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
        }
    }
}

fn derive_key(key: &KeyFile, password: &String) -> Result<DerivedKey, CipherError> {
    match key.kdf {
        Kdf::Pbkdf2 { c, .. } => {
            let mut hmac_f = Hmac::new(Sha256::new(), password.as_bytes());
            let mut derived = [0u8; 32];
            pbkdf2(&mut hmac_f, &key.kdf_salt, c, &mut derived);
            Ok(derived)
        }
        Kdf::Scrypt { n, r, p } => {
            let log_n = (n as f64).log2().round() as u8; //TODO validate
            let params = ScryptParams::new(log_n, r, p);
            let mut derived = [0u8; 32];
            scrypt(password.as_bytes(), &key.kdf_salt, &params, &mut derived);
            Ok(derived)
        }
    }
}

fn prepare_mac(key: &KeyFile, derived: DerivedKey) -> Result<MAC, CipherError> {
    let mut sha3 = Sha3::new(Sha3Mode::Keccak256);
    let mut mac: MAC = [0u8; 32];
    sha3.input(&derived[16..32]);
    sha3.input(&key.cipher_text.as_slice());
    sha3.result(&mut mac);
    Ok(mac)
}

impl GetPkey for KeyFile {
    fn get_pk(&self, password: String) -> Result<PrivateKey, CipherError> {
        let derived = derive_key(&self, &password)?;
        let mac = prepare_mac(&self, derived)?;

        if mac != self.keccak256_mac {
            return Err(CipherError::InvalidMAC {
                           exp: self.keccak256_mac,
                           act: mac,
                       });
        }

        let mut cipher = ctr(KeySize::KeySize128, &derived[0..16], &self.cipher_iv);
        let mut pkey = [0u8; 32];
        cipher.process(&self.cipher_text.as_slice(), &mut pkey);
        Ok(pkey)
    }
}

#[cfg(test)]
pub mod tests {
    use super::{GetPkey, derive_key, prepare_mac};
    use keystore::{CIPHER_IV_BYTES, Cipher, KDF_SALT_BYTES, KECCAK256_BYTES, Kdf, KeyFile, Prf};
    use rustc_serialize::hex::{FromHex, ToHex};
    use std::str::FromStr;
    use uuid::Uuid;

    macro_rules! arr {
        ($bytes: expr, $num: expr) => ({
            let mut arr = [0; $num];

            arr.clone_from_slice($bytes);

            arr
        })
    }

    // [Test vectors](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition)

    fn test_vector_1() -> KeyFile {
        KeyFile {
            uuid: Uuid::from_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap(),
            address: None,
            cipher: Cipher::default(),
            cipher_iv: arr!(&"6087dab2f9fdbbfaddc31a909735c1e6".from_hex().unwrap(),
                            CIPHER_IV_BYTES),
            cipher_text: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
                .from_hex()
                .unwrap(),
            kdf: Kdf::Pbkdf2 {
                prf: Prf::default(),
                c: 262144,
            },
            kdf_salt: arr!(&"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                                .from_hex()
                                .unwrap(),
                           KDF_SALT_BYTES),
            keccak256_mac: arr!(&"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
                                    .from_hex()
                                    .unwrap(),
                                KECCAK256_BYTES),
            dk_length: 32,
        }
    }

    fn test_vector_2() -> KeyFile {
        KeyFile {
            uuid: Uuid::from_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap(),
            address: None,
            cipher: Cipher::default(),
            cipher_iv: arr!(&"83dbcc02d8ccb40e466191a123791e0e".from_hex().unwrap(),
                            CIPHER_IV_BYTES),
            cipher_text: "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c"
                .from_hex()
                .unwrap(),
            kdf: Kdf::Scrypt {
                n: 262144,
                r: 8,
                p: 1,
            },
            kdf_salt: arr!(&"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                                .from_hex()
                                .unwrap(),
                           KDF_SALT_BYTES),
            keccak256_mac: arr!(&"2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
                                    .from_hex()
                                    .unwrap(),
                                KECCAK256_BYTES),
            dk_length: 32,
        }
    }

    #[test]
    fn should_derive_key_tv1() {
        let key = test_vector_1();
        assert_eq!(derive_key(&key, &"testpassword".to_string()).unwrap(),
                   "f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551"
                       .from_hex()
                       .unwrap()
                       .as_slice())
    }

    #[test]
    fn should_mac_tv1() {
        let key = test_vector_1();
        let derived_key = arr!(&"f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551"
                                    .from_hex()
                                    .unwrap(),
                               KECCAK256_BYTES);
        assert_eq!(prepare_mac(&key, derived_key).unwrap().to_hex(),
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

    #[test]
    #[ignore]
    fn should_derive_key_tv2() {
        let key = test_vector_2();
        assert_eq!(derive_key(&key, &"testpassword".to_string()).unwrap(),
                   "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd"
                       .from_hex()
                       .unwrap()
                       .as_slice())
    }

    #[test]
    fn should_mac_tv2() {
        let key = test_vector_2();
        let derived_key = arr!(&"fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd"
                                    .from_hex()
                                    .unwrap(),
                               KECCAK256_BYTES);
        assert_eq!(prepare_mac(&key, derived_key).unwrap().to_hex(),
                   "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097")
    }

    #[test]
    fn should_get_pk_tv2() {
        let key = test_vector_2();
        assert_eq!(key.get_pk("testpassword".to_string()).unwrap(),
                   "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
                       .from_hex()
                       .unwrap()
                       .as_slice());
    }
}
