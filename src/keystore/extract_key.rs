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

#[cfg(test)]
pub mod tests {
    use keystore::{Cipher, Kdf, KeyFile, Prf};
    use rustc_serialize::hex::{FromHex, ToHex};
    use std::str::FromStr;
    use uuid::Uuid;

    fn as_16bytes(hex: &str) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(hex.from_hex().unwrap().as_slice());
        buf
    }

    fn as_32bytes(hex: &str) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(hex.from_hex().unwrap().as_slice());
        buf
    }

    // Test Vectors from https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition

    fn test_vector_1() -> KeyFile {
        KeyFile {
            uuid: Uuid::from_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap(),
            address: None,
            cipher: Cipher::default(),
            cipher_iv: as_16bytes("6087dab2f9fdbbfaddc31a909735c1e6"),
            cipher_text: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
                .from_hex()
                .unwrap(),
            kdf: Kdf::Pbkdf2 {
                prf: Prf::default(),
                c: 262144,
            },
            kdf_salt:
            as_32bytes("ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"),
            keccak256_mac:
            as_32bytes("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"),
            dk_length: 32,
        }
    }

    fn test_vector_2() -> KeyFile {
        KeyFile {
            uuid: Uuid::from_str("f7ab2bfa-e336-4f45-a31f-beb3dd0689f3").unwrap(),
            address: Some("0x0047201aed0b69875b24b614dda0270bcd9f11cc"
                .parse()
                .unwrap()),
            cipher: Cipher::default(),
            cipher_iv: as_16bytes("9df1649dd1c50f2153917e3b9e7164e9"),
            cipher_text: "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1"
                .from_hex()
                .unwrap(),
            kdf: Kdf::Scrypt {
                n: 1024,
                r: 8,
                p: 1,
            },
            kdf_salt:
            as_32bytes("fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4"),
            keccak256_mac:
            as_32bytes("9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5"),
            dk_length: 32,
        }
    }

    #[test]
    fn should_derive_key_tv1() {
        assert_eq!(test_vector_1().derive_key("testpassword").to_hex(),
        "f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551")
    }

    #[test]
    fn should_mac_tv1() {
        let derived_key =
            as_32bytes("f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551");

        assert_eq!(test_vector_1().calculate_mac(&derived_key).to_hex(),
        "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
    }

    #[test]
    fn should_get_pk_tv1() {
        assert_eq!(test_vector_1()
            .extract_key("testpassword")
            .unwrap()
            .to_hex(),
        "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d");
    }

    #[test]
    fn should_derive_key_tv2() {
        assert_eq!(test_vector_2().derive_key("1234567890").to_hex(),
        "b424c7c40d2409b8b7dce0d172bda34ca70e57232eb74db89396b55304dbe273")
    }

    #[test]
    fn should_mac_tv2() {
        let derived_key =
            as_32bytes("b424c7c40d2409b8b7dce0d172bda34ca70e57232eb74db89396b55304dbe273");

        assert_eq!(test_vector_2().calculate_mac(&derived_key).to_hex(),
        "9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5")
    }

    #[test]
    fn should_get_pk_tv2() {
        assert_eq!(test_vector_2()
            .extract_key("1234567890")
            .unwrap()
            .to_hex(),
        "fa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f");
    }
}
