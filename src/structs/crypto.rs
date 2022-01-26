use std::convert::TryInto;
use rand::RngCore;
use rand::rngs::OsRng;
use crate::crypto::error::CryptoError;
use crate::storage::error::VaultError;
use crate::structs::types::{IsVerified, UsesGlobalKey};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScryptKdf {
    pub dklen: u32,
    pub salt: Vec<u8>,
    pub n: u32,
    pub r: u32,
    pub p: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pbkdf2 {
    pub dklen: u32,
    pub c: u32,
    pub salt: Vec<u8>,
    pub prf: PrfType,
}

/*
    Default type of KDF
 */
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Argon2 {
    pub mem: u32,
    pub iterations: u32,
    pub parallel: u32,
    pub salt: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PrfType {
    HmacSha256,
    HmacSha512,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Kdf {
    Scrypt(ScryptKdf),
    Pbkdf2(Pbkdf2),
    Argon2(Argon2),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Encrypted {
    pub cipher: Cipher,
    pub kdf: Kdf,
    /// When set the encryption key is derived from a Global Key
    pub global_key: Option<GlobalKeyRef>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Cipher {
    Aes128Ctr(Aes128CtrCipher),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Aes128CtrCipher {
    pub encrypted: Vec<u8>,
    pub iv: Vec<u8>,
    pub mac: MacType,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MacType {
    Web3(Vec<u8>),
}

///
/// Reference to use when generating subkey from a global key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GlobalKeyRef {
    ///
    /// Random nonce used for Key Derivation from Global Key
    pub nonce: [u8; 16],
}

///
/// Global Key. I.e., a key that used a main source to derive a subkey for different items (private keys, seed, etc)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GlobalKey {
    pub key: Encrypted,
}

impl Encrypted {
    pub fn get_mac(&self) -> &Vec<u8> {
        match &self.cipher {
            Cipher::Aes128Ctr(v) => match &v.mac {
                MacType::Web3(x) => x,
            },
        }
    }

    pub fn get_iv(&self) -> &Vec<u8> {
        match &self.cipher {
            Cipher::Aes128Ctr(v) => &v.iv,
        }
    }

    pub fn get_message(&self) -> &Vec<u8> {
        match &self.cipher {
            Cipher::Aes128Ctr(v) => &v.encrypted,
        }
    }
}

impl UsesGlobalKey for Encrypted {
    fn is_using_global(&self) -> bool {
        self.global_key.is_some()
    }
}

impl IsVerified for ScryptKdf {
    fn verify(self) -> Result<Self, String> {
        if self.salt.len() != 32 {
            return Err("salt has invalid size".to_string());
        }
        if self.dklen != 32 {
            return Err("dklen has invalid value".to_string());
        }
        if self.p <= 0 {
            return Err("p is too small".to_string());
        }
        if self.n <= 0 {
            return Err("n is too small".to_string());
        }
        if self.r <= 0 {
            return Err("r is too small".to_string());
        }
        Ok(self)
    }
}

impl GlobalKeyRef {
    ///
    /// Build Global Kye Ref with provided `nonce`
    pub(crate) fn create(nonce: Vec<u8>) -> Result<GlobalKeyRef, VaultError> {
        let nonce = nonce.try_into()
            .map_err(|_| VaultError::UnsupportedDataError("nonce size".to_string()))?;
        Ok(GlobalKeyRef {
            nonce
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::structs::crypto::{Encrypted, GlobalKey};

    #[test]
    fn tells_that_global_key_is_used() {
        let global = GlobalKey::generate("test-g".as_bytes()).unwrap();
        let direct = Encrypted::encrypt("test".as_bytes().to_vec(), "test-g".as_bytes(), None).unwrap();
        let with_global = Encrypted::encrypt("test".as_bytes().to_vec(), "test-g".as_bytes(), Some(global)).unwrap();
        assert!(!direct.is_using_global());
        assert!(with_global.is_using_global());
    }
}
