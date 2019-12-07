use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewFixStreamCipher, StreamCipherCore};
use aes_ctr::Aes128Ctr;
use rand::prelude::{Rng};
use rand::thread_rng;
use std::convert::TryFrom;
use crate::convert::proto::crypto::{Encrypted, Cipher, MacType, Aes128CtrCipher, ScryptKdf, Kdf};
use crate::keccak256;
use crate::crypto::error::CryptoError;
use crate::crypto::kdf::KeyDerive;


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
    pub fn encrypt(msg: Vec<u8>, password: &str) -> Result<Encrypted, CryptoError> {
        let mut salt: [u8; 32] = [0; 32];
        thread_rng().try_fill(&mut salt);
        let kdf = ScryptKdf::create_with_salt(salt);
        let key = kdf.derive(password)?;

        let mut iv: [u8; 16] = [0; 16];
        thread_rng().try_fill(&mut iv);
        let key = Web3Key::try_from(key)?;
        let encrypted = encrypt_aes128(msg.as_slice(), &key.message_key, &iv);
        let result = Encrypted {
            cipher: Cipher::Aes128Ctr(
                Aes128CtrCipher {
                    encrypted: encrypted.clone(),
                    iv: iv.to_vec(),
                    mac: MacType::sign_web3(&key.mac_key.to_vec(), encrypted)?
                }
            ),
            kdf: Kdf::Scrypt(kdf)
        };
        Ok(result)
    }

    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, CryptoError> {
        let key = self.kdf.derive(password)?;
        let msg = self.cipher.decrypt_value(key)?;
        Ok(msg)
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
        let mut message_key : [u8; 16] = [0; 16];
        let mut mac_key : [u8; 16] = [0; 16];
        message_key.copy_from_slice(&key[0..16]);
        mac_key.copy_from_slice(&key[16..]);
        Ok(Web3Key {
            message_key,
            mac_key
        })
    }
}

impl Cipher {
    pub fn decrypt_value(&self, key: Vec<u8>) -> Result<Vec<u8>,CryptoError> {
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
    fn sign_web3(key: &Vec<u8>, message: Vec<u8>) -> Result<MacType,CryptoError> {
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

#[cfg(test)]
mod tests {
    use crate::convert::proto::crypto::{MacType, Encrypted, Cipher, Aes128CtrCipher};
    use crate::crypto::error::CryptoError;
    use crate::crypto::encrypted::{Web3Key, encrypt_aes128, decrypt_aes128};
    use std::convert::TryFrom;

    #[test]
    fn verify_mac_1() {
        let mac = MacType::Web3(hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2").unwrap());
        let ciphertext = hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46").unwrap();
        let mac_passwd = hex::decode("e31891a3a773950e6d0fea48a7188551").unwrap();
        // mac body = e31891a3a773950e6d0fea48a71885515318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46
        //   = e31891a3a773950e6d0fea48a7188551 + 5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46
        let act = mac.verify(&mac_passwd, &ciphertext);
        assert!(act)
    }

    #[test]
    fn verify_mac_2() {
        let mac = MacType::Web3(hex::decode("2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097").unwrap());
        let ciphertext = hex::decode("d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c").unwrap();
        let mac_password = hex::decode("bb5cc24229e20d8766fd298291bba6bd").unwrap();
        let act = mac.verify(&mac_password, &ciphertext);
        assert!(act)
    }

    #[test]
    fn deny_invalid_mac() {
        let mac = MacType::Web3(hex::decode("617ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2").unwrap());
        let ciphertext = hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46").unwrap();
        let pk = hex::decode("e31891a3a773950e6d0fea48a7188551").unwrap();
        let act = mac.verify(&pk, &ciphertext);
        assert!(!act);

        let mac = MacType::Web3(hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2").unwrap());
        let ciphertext = hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46").unwrap();
        let pk = hex::decode("e31891a3a773950e6d0fea48a7188552").unwrap();
        let act = mac.verify(&pk, &ciphertext);
        assert!(!act);

        let mac = MacType::Web3(hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2").unwrap());
        let ciphertext = hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa47").unwrap();
        let pk = hex::decode("e31891a3a773950e6d0fea48a7188551").unwrap();
        let act = mac.verify(&pk, &ciphertext);
        assert!(!act);
    }

    #[test]
    fn decrypt_std_1() {
        let encrypted = Cipher::Aes128Ctr(
            Aes128CtrCipher {
                encrypted: hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46").unwrap(),
                iv: hex::decode("6087dab2f9fdbbfaddc31a909735c1e6").unwrap(),
                mac: MacType::Web3(
                    hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2").unwrap()
                )
            },
        );
        let key = hex::decode("f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551").unwrap();

        let act = encrypted.decrypt_value(key);
        assert!(act.is_ok());
        assert_eq!(
            "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
            hex::encode(act.unwrap().as_slice())
        )
    }

    #[test]
    fn fail_to_decrypt_with_wrong_key() {
        let encrypted = Cipher::Aes128Ctr(
            Aes128CtrCipher {
                encrypted: hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46").unwrap(),
                iv: hex::decode("6087dab2f9fdbbfaddc31a909735c1e6").unwrap(),
                mac: MacType::Web3(
                    hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2").unwrap()
                )
            },
        );
        let key = hex::decode("f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188552").unwrap();

        let act = encrypted.decrypt_value(key);
        assert!(act.is_err());
        assert_eq!(CryptoError::WrongKey, act.err().unwrap())
    }

    #[test]
    fn encrypt_0xfac192ce() {
        let encrypted = Encrypted::encrypt(
            hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd").unwrap(),
            "test");

        assert!(encrypted.is_ok());

        let decrypted = encrypted.unwrap().decrypt("test");
//        println!("{:?}", decrypted.err());
        assert!(decrypted.is_ok());
        assert_eq!(
            "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd",
            hex::encode(decrypted.unwrap())
        )
    }

    #[test]
    fn split_web3_key() {
        let key = Web3Key::try_from(hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd").unwrap());
        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!("fac192ceb5fd772906bea3e118a69e8b", hex::encode(key.message_key));
        assert_eq!("bb5cc24229e20d8766fd298291bba6bd", hex::encode(key.mac_key));
    }

    #[test]
    fn encrypt_descrypt_aes128() {
        let encrypted = encrypt_aes128(
            hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd").unwrap().as_slice(),
            hex::decode("fac192ceb5fd772906bea3e118a69e8b").unwrap().as_slice(),
            hex::decode("bb5cc24229e20d8766fd298291bba6bd").unwrap().as_slice(),
        );

        assert!(encrypted.len() > 0);

        let decrypted = decrypt_aes128(
            encrypted.as_slice(),
            hex::decode("fac192ceb5fd772906bea3e118a69e8b").unwrap().as_slice(),
            hex::decode("bb5cc24229e20d8766fd298291bba6bd").unwrap().as_slice(),
        );

        assert_eq!(
            "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd",
            hex::encode(decrypted)
        )
    }
}
