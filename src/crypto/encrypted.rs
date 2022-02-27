use crate::{
    crypto::{error::CryptoError, kdf::KeyDerive},
    keccak256,
    structs::crypto::{Aes128CtrCipher, Cipher, Encrypted, Kdf, MacType, ScryptKdf},
};
use aes_ctr::Aes128Ctr;
use aes_ctr::cipher::{
    stream::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher},
};
use rand::{prelude::Rng, RngCore, thread_rng};
use std::convert::TryFrom;
use rand::rngs::OsRng;
use crate::structs::crypto::{Argon2, GlobalKey, GlobalKeyRef};

/// Encrypt given text with provided key and initial vector
fn encrypt_aes128(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    let mut buf = data.to_vec();
    let mut ctr = Aes128Ctr::new(key, iv);
    ctr.apply_keystream(&mut buf);
    buf
}

fn decrypt_aes128(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    let mut buf = data.to_vec();
    let mut ctr = Aes128Ctr::new(key, iv);
    ctr.apply_keystream(&mut buf);
    buf
}

impl Encrypted {
    pub fn encrypt(msg: Vec<u8>, password: &[u8], global: Option<GlobalKey>) -> Result<Encrypted, CryptoError> {
        // for security reasons shouldn't allow empty passwords
        if password.len() == 0 {
            return Err(CryptoError::InvalidKey);
        }

        let actual_password = match &global {
            Some(global) => {
                let key_ref = GlobalKeyRef::new()?;
                let msg_password = global.get_password(password, &key_ref.nonce)?;
                (msg_password.to_vec(), Some(key_ref))
            },
            None => (password.to_vec(), None)
        };

        // see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-10
        // > Select the salt length. 128 bits is sufficient for all
        // > applications, but can be reduced to 64 bits in the case of space
        // > constraints.
        let mut salt: [u8; 16] = [0; 16];
        thread_rng()
            .try_fill(&mut salt)
            .map_err(|_| CryptoError::NoEntropy)?;
        let kdf = match global {
            Some(_) => Argon2::new_subkey(salt.to_vec()),
            None => Argon2::new_global(salt.to_vec())
        };
        // println!("Use KDF: {:} {:} {:}", kdf.mem, kdf.iterations, kdf.parallel);
        let key = kdf.derive(actual_password.0.as_slice())?;

        let mut iv: [u8; 16] = [0; 16];
        OsRng::new()?
            .try_fill(&mut iv)
            .map_err(|_| CryptoError::NoEntropy)?;
        let key = Web3Key::try_from(key)?;
        let encrypted = encrypt_aes128(msg.as_slice(), &key.message_key, &iv);
        let result = Encrypted {
            cipher: Cipher::Aes128Ctr(Aes128CtrCipher {
                encrypted: encrypted.clone(),
                iv: iv.to_vec(),
                mac: MacType::sign_web3(&key.mac_key.to_vec(), encrypted)?,
            }),
            kdf: Kdf::Argon2(kdf),
            global_key: actual_password.1
        };
        Ok(result)
    }

    ///
    /// Decrypt and encrypt the current Secret again, with a new nonce, etc. It supposed to actualize encryption
    /// schema to the current one. Ex. if an old Secret with individual password is provided it's re-encrypted
    /// using a Global Key.
    ///
    /// Params:
    /// - `prev_password` - used only if a legacy secret gets re-encrypted, otherwise None
    /// - `global_password` - global key password
    /// - `global` - global key
    pub fn reencrypt(self, prev_password: Option<&[u8]>, global_password: &[u8], global: GlobalKey) -> Result<Encrypted, CryptoError> {
        let msg = if self.is_using_global() {
            self.decrypt(global_password, Some(global.clone()))?
        } else {
            if prev_password.is_none() {
                return Err(CryptoError::PasswordRequired)
            }
            self.decrypt(prev_password.unwrap(), None)?
        };
        Encrypted::encrypt(msg, global_password, Some(global))
    }

    /*
    For backward compatibility with ethereum keys provided as JSON. Such files are supposed to use Scrypt or PBKDF2 KDF
     */
    #[deprecated] // need to just decrypt them and import as normal
    pub fn encrypt_ethereum(msg: Vec<u8>, password: &[u8]) -> Result<Encrypted, CryptoError> {
        // for security reasons shouldn't allow empty passwords
        if password.len() == 0 {
            return Err(CryptoError::InvalidKey);
        }
        let mut salt: [u8; 32] = [0; 32];
        thread_rng()
            .try_fill(&mut salt)
            .map_err(|_| CryptoError::NoEntropy)?;
        let kdf = ScryptKdf::create_with_salt(salt);
        let key = kdf.derive(password)?;

        let mut iv: [u8; 16] = [0; 16];
        thread_rng()
            .try_fill(&mut iv)
            .map_err(|_| CryptoError::NoEntropy)?;
        let key = Web3Key::try_from(key)?;
        let encrypted = encrypt_aes128(msg.as_slice(), &key.message_key, &iv);
        let result = Encrypted {
            cipher: Cipher::Aes128Ctr(Aes128CtrCipher {
                encrypted: encrypted.clone(),
                iv: iv.to_vec(),
                mac: MacType::sign_web3(&key.mac_key.to_vec(), encrypted)?,
            }),
            kdf: Kdf::Scrypt(kdf),
            //TODO
            global_key: None,
        };
        Ok(result)
    }

    pub fn decrypt(&self, password: &[u8], global: Option<GlobalKey>) -> Result<Vec<u8>, CryptoError> {
        let actual_password = if self.is_using_global() {
            if global.is_none() {
                return Err(CryptoError::GlobalKeyRequired)
            }
            let temp = global.unwrap().get_password(password, &self.global_key.as_ref().unwrap().nonce)?;
            temp.to_vec()
        } else {
            password.to_vec()
        };
        let key = self.kdf.derive(actual_password.as_slice())?;
        let msg = self.cipher.decrypt_value(key)?;
        Ok(msg)
    }

    pub fn is_using_global(&self) -> bool {
        self.global_key.is_some()
    }
}

struct Web3Key {
    pub message_key: [u8; 16],
    pub mac_key: [u8; 16],
}

impl TryFrom<Vec<u8>> for Web3Key {
    type Error = CryptoError;

    fn try_from(key: Vec<u8>) -> Result<Self, Self::Error> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        // left part of the key is Msg key, right part is Mac key
        let mut message_key: [u8; 16] = [0; 16];
        let mut mac_key: [u8; 16] = [0; 16];
        message_key.copy_from_slice(&key[0..16]);
        mac_key.copy_from_slice(&key[16..]);
        Ok(Web3Key {
            message_key,
            mac_key,
        })
    }
}

impl Cipher {
    pub fn decrypt_value(&self, key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        match &self {
            Cipher::Aes128Ctr(conf) => {
                let key = Web3Key::try_from(key)?;
                let iv = &conf.iv;
                let data = &conf.encrypted;
                let decrypted = decrypt_aes128(data.as_slice(), &key.message_key, iv.as_slice());

                let verified = conf.mac.verify(&key.mac_key.to_vec(), &conf.encrypted);
                if verified {
                    Ok(decrypted)
                } else {
                    Err(CryptoError::WrongKey)
                }
            }
        }
    }
}

impl MacType {
    fn verify(&self, key: &Vec<u8>, message: &Vec<u8>) -> bool {
        match self {
            MacType::Web3(mac) => {
                if key.len() != 16 {
                    return false;
                }
                let mut msg: Vec<u8> = Vec::new();
                msg.extend_from_slice(key);
                msg.extend_from_slice(message.as_slice());
                let hash = keccak256(msg.as_slice());
                hash == mac.as_slice()
            }
        }
    }
}

impl MacType {
    fn sign_web3(key: &Vec<u8>, message: Vec<u8>) -> Result<MacType, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKey);
        }
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(key);
        msg.extend_from_slice(message.as_slice());
        let hash = keccak256(msg.as_slice());
        Ok(MacType::Web3(hash.to_vec()))
    }
}

impl GlobalKey {
    pub fn get_password(&self, base_password: &[u8], nonce: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
        let base = self.key.decrypt(base_password, None)?;
        let kdf = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::default(),
            // use a very basic KDF options because this one is used only to produce different base key,
            // which in its turn uses a more advanced KDF for encryption. I.e. both Global Key and Secret keys
            // use different Argon2 or other KDF.
            argon2::Params::new(
                128,
                2,
                1,
                Some(32),
            )?,
        );
        let mut key = [0u8; 32];
        kdf.hash_password_into(base.as_slice(), nonce, &mut key)?;
        Ok(key)
    }

    pub fn generate(base_password: &[u8]) -> Result<GlobalKey, CryptoError> {
        let mut key = [0u8; 32];
        OsRng::new()?.fill_bytes(&mut key);
        Ok(
            GlobalKey {
                key: Encrypted::encrypt(key.to_vec(), base_password, None)?
            }
        )
    }
}

impl GlobalKeyRef {
    ///
    /// Create new Global Key Ref with a new randomly generated `nonce`
    pub fn new() -> Result<GlobalKeyRef, CryptoError> {
        let mut nonce = [0u8; 16];
        OsRng::new()?.fill_bytes(&mut nonce);

        Ok(GlobalKeyRef {
            nonce
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{
            encrypted::{decrypt_aes128, encrypt_aes128, Web3Key},
            error::CryptoError,
        },
        structs::crypto::{Aes128CtrCipher, Cipher, Encrypted, MacType},
    };
    use std::convert::TryFrom;
    use crate::structs::crypto::{GlobalKey, GlobalKeyRef};

    #[test]
    fn verify_mac_1() {
        let mac = MacType::Web3(
            hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
                .unwrap(),
        );
        let ciphertext =
            hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46")
                .unwrap();
        let mac_passwd = hex::decode("e31891a3a773950e6d0fea48a7188551").unwrap();
        // mac body = e31891a3a773950e6d0fea48a71885515318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46
        //   = e31891a3a773950e6d0fea48a7188551 + 5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46
        let act = mac.verify(&mac_passwd, &ciphertext);
        assert!(act)
    }

    #[test]
    fn verify_mac_2() {
        let mac = MacType::Web3(
            hex::decode("2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097")
                .unwrap(),
        );
        let ciphertext =
            hex::decode("d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c")
                .unwrap();
        let mac_password = hex::decode("bb5cc24229e20d8766fd298291bba6bd").unwrap();
        let act = mac.verify(&mac_password, &ciphertext);
        assert!(act)
    }

    #[test]
    fn deny_invalid_mac() {
        let mac = MacType::Web3(
            hex::decode("617ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
                .unwrap(),
        );
        let ciphertext =
            hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46")
                .unwrap();
        let pk = hex::decode("e31891a3a773950e6d0fea48a7188551").unwrap();
        let act = mac.verify(&pk, &ciphertext);
        assert!(!act);

        let mac = MacType::Web3(
            hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
                .unwrap(),
        );
        let ciphertext =
            hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46")
                .unwrap();
        let pk = hex::decode("e31891a3a773950e6d0fea48a7188552").unwrap();
        let act = mac.verify(&pk, &ciphertext);
        assert!(!act);

        let mac = MacType::Web3(
            hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
                .unwrap(),
        );
        let ciphertext =
            hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa47")
                .unwrap();
        let pk = hex::decode("e31891a3a773950e6d0fea48a7188551").unwrap();
        let act = mac.verify(&pk, &ciphertext);
        assert!(!act);
    }

    #[test]
    fn decrypt_std_1() {
        let encrypted = Cipher::Aes128Ctr(Aes128CtrCipher {
            encrypted: hex::decode(
                "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
            )
            .unwrap(),
            iv: hex::decode("6087dab2f9fdbbfaddc31a909735c1e6").unwrap(),
            mac: MacType::Web3(
                hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
                    .unwrap(),
            ),
        });
        let key = hex::decode("f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551")
            .unwrap();

        let act = encrypted.decrypt_value(key);
        assert!(act.is_ok());
        assert_eq!(
            "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
            hex::encode(act.unwrap().as_slice())
        )
    }

    #[test]
    fn fail_to_decrypt_with_wrong_key() {
        let encrypted = Cipher::Aes128Ctr(Aes128CtrCipher {
            encrypted: hex::decode(
                "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
            )
            .unwrap(),
            iv: hex::decode("6087dab2f9fdbbfaddc31a909735c1e6").unwrap(),
            mac: MacType::Web3(
                hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
                    .unwrap(),
            ),
        });
        let key = hex::decode("f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188552")
            .unwrap();

        let act = encrypted.decrypt_value(key);
        assert!(act.is_err());
        assert_eq!(CryptoError::WrongKey, act.err().unwrap())
    }

    #[test]
    fn encrypt_0xfac192ce() {
        let encrypted = Encrypted::encrypt(
            hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                .unwrap(),
            "test".as_bytes(),
            None,
        );

        assert!(encrypted.is_ok());

        let decrypted = encrypted.unwrap().decrypt("test".as_bytes(), None);
        //        println!("{:?}", decrypted.err());
        assert!(decrypted.is_ok());
        assert_eq!(
            "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd",
            hex::encode(decrypted.unwrap())
        )
    }

    #[test]
    fn encrypt_0000() {
        let encrypted = Encrypted::encrypt(
            hex::decode("00")
                .unwrap(),
            "test".as_bytes(),
            None,
        );

        assert!(encrypted.is_ok());

        let decrypted = encrypted.unwrap().decrypt("test".as_bytes(), None);
        //        println!("{:?}", decrypted.err());
        assert!(decrypted.is_ok());
        assert_eq!(
            "00",
            hex::encode(decrypted.unwrap())
        )
    }

    #[test]
    fn split_web3_key() {
        let key = Web3Key::try_from(
            hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                .unwrap(),
        );
        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!(
            "fac192ceb5fd772906bea3e118a69e8b",
            hex::encode(key.message_key)
        );
        assert_eq!("bb5cc24229e20d8766fd298291bba6bd", hex::encode(key.mac_key));
    }

    #[test]
    fn encrypt_descrypt_aes128() {
        let encrypted = encrypt_aes128(
            hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                .unwrap()
                .as_slice(),
            hex::decode("fac192ceb5fd772906bea3e118a69e8b")
                .unwrap()
                .as_slice(),
            hex::decode("bb5cc24229e20d8766fd298291bba6bd")
                .unwrap()
                .as_slice(),
        );

        assert!(encrypted.len() > 0);

        let decrypted = decrypt_aes128(
            encrypted.as_slice(),
            hex::decode("fac192ceb5fd772906bea3e118a69e8b")
                .unwrap()
                .as_slice(),
            hex::decode("bb5cc24229e20d8766fd298291bba6bd")
                .unwrap()
                .as_slice(),
        );

        assert_eq!(
            "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd",
            hex::encode(decrypted)
        )
    }

    #[test]
    fn doesnt_allow_empty_passwrod() {
        let act = Encrypted::encrypt(
            hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                .unwrap(),
            "".as_bytes(),
            None,
        );
        assert!(act.is_err());
        assert_eq!(CryptoError::InvalidKey, act.err().unwrap());
    }

    #[test]
    fn generates_diff_nonce() {
        let r1 = GlobalKeyRef::new().unwrap();
        let r2 = GlobalKeyRef::new().unwrap();

        assert_ne!(hex::encode(r1.nonce), hex::encode(r2.nonce));
    }


    #[test]
    fn diff_password_per_nonce() {
        let r1 = GlobalKeyRef::create(hex::decode("00000000000000000000000000000000").unwrap()).unwrap();
        let r2 = GlobalKeyRef::create(hex::decode("00000000000000000000000000000001").unwrap()).unwrap();

        let key = GlobalKey {
            key: Encrypted::encrypt("test message".as_bytes().to_vec(), "test".as_bytes(), None).unwrap()
        };

        let key1 = key.get_password("test".as_bytes(), &r1.nonce).unwrap();
        let key2 = key.get_password("test".as_bytes(), &r2.nonce).unwrap();

        println!("{:?} {:?}", hex::encode(&key1), hex::encode(&key2));
        assert_ne!(hex::encode(key1), hex::encode(key2));
    }

    #[test]
    fn reencrypt_from_legacy() {
        let legacy = Encrypted::encrypt(
            "test-msg".as_bytes().to_vec(),
            "test".as_bytes(),
            None,
        ).unwrap();

        let global = GlobalKey::generate("test-g".as_bytes()).unwrap();

        let new = legacy.reencrypt(Some("test".as_bytes()), "test-g".as_bytes(), global.clone()).unwrap();
        assert!(new.is_using_global());
        let msg = new.decrypt("test-g".as_bytes(), Some(global));
        assert!(msg.is_ok());
        let msg = String::from_utf8(msg.unwrap()).unwrap();
        assert_eq!(msg, "test-msg".to_string());
    }

    #[test]
    fn reencrypt_from_global() {
        let global = GlobalKey::generate("test-g".as_bytes()).unwrap();

        let v1 = Encrypted::encrypt(
            "test-msg".as_bytes().to_vec(),
            "test-g".as_bytes(),
            Some(global.clone()),
        ).unwrap();

        let v2 = v1.reencrypt(None, "test-g".as_bytes(), global.clone()).unwrap();
        assert!(v2.is_using_global());
        let msg = v2.decrypt("test-g".as_bytes(), Some(global));
        assert!(msg.is_ok());
        let msg = String::from_utf8(msg.unwrap()).unwrap();
        assert_eq!(msg, "test-msg".to_string());
    }

    #[test]
    fn no_reencrypt_wrong_password() {
        let legacy = Encrypted::encrypt(
            "test-msg".as_bytes().to_vec(),
            "test".as_bytes(),
            None,
        ).unwrap();

        let global = GlobalKey::generate("test-g".as_bytes()).unwrap();

        let new = legacy.reencrypt(Some("test-wrong".as_bytes()), "test-g".as_bytes(), global.clone());
        assert!(new.is_err());
    }

    #[test]
    fn no_reencrypt_empty_password() {
        let legacy = Encrypted::encrypt(
            "test-msg".as_bytes().to_vec(),
            "test".as_bytes(),
            None,
        ).unwrap();

        let global = GlobalKey::generate("test-g".as_bytes()).unwrap();

        let new = legacy.reencrypt(None, "test-g".as_bytes(), global.clone());
        assert!(new.is_err());
    }
}
