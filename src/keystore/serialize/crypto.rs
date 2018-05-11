//! # JSON serialize for crypto field (UTC / JSON)

use super::util::KECCAK256_BYTES;
use super::{Cipher, CryptoType, Error, KdfParams, KeyFile, Salt, CIPHER_IV_BYTES};
use hex::{FromHex, ToHex};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::default::Default;

byte_array_struct!(Mac, KECCAK256_BYTES);
byte_array_struct!(Iv, CIPHER_IV_BYTES);

/// `Keyfile` related crypto attributes
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreCrypto {
    /// Cipher
    pub cipher: Cipher,

    /// Cipher text
    pub cipher_text: Vec<u8>,

    /// Params for `Cipher`
    pub cipher_params: CipherParams,

    /// Key derivation funciton
    pub kdf_params: KdfParams,

    /// HMAC authentication code
    pub mac: Mac,
}

/// Serialization representation for `CoreCrypto`
#[derive(Serialize, Deserialize, Debug)]
struct SerCoreCrypto {
    pub cipher: Cipher,

    #[serde(rename = "ciphertext")]
    pub cipher_text: String,

    #[serde(rename = "cipherparams")]
    pub cipher_params: CipherParams,

    pub kdf: String,

    #[serde(rename = "kdfparams")]
    pub kdf_params: KdfParams,

    pub mac: Mac,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CipherParams {
    pub iv: Iv,
}

impl Default for CipherParams {
    fn default() -> Self {
        CipherParams {
            iv: Iv::from([0; CIPHER_IV_BYTES]),
        }
    }
}

impl CoreCrypto {
    /// Try to create crypto attributes from
    /// corresponding Keyfile (simple or HDWallet keyfile)
    pub fn try_from(kf: &KeyFile) -> Result<Self, Error> {
        match kf.crypto {
            CryptoType::Core(ref core) => Ok(CoreCrypto {
                cipher: core.cipher,
                cipher_text: core.cipher_text.clone(),
                cipher_params: core.cipher_params.clone(),
                kdf_params: KdfParams {
                    kdf: core.kdf_params.kdf,
                    dklen: core.kdf_params.dklen,
                    salt: Salt::from(core.kdf_params.salt.0),
                },
                mac: Mac::from(core.mac.0),
            }),
            _ => Err(Error::NotFound),
        }
    }
}

impl Default for CoreCrypto {
    fn default() -> Self {
        Self {
            cipher: Cipher::default(),
            cipher_text: vec![],
            cipher_params: CipherParams::default(),
            kdf_params: KdfParams::default(),
            mac: Mac::default(),
        }
    }
}

impl Into<KeyFile> for CoreCrypto {
    fn into(self) -> KeyFile {
        KeyFile {
            crypto: CryptoType::Core(self),
            ..Default::default()
        }
    }
}

impl From<SerCoreCrypto> for CoreCrypto {
    fn from(ser: SerCoreCrypto) -> Self {
        CoreCrypto {
            cipher: ser.cipher,
            cipher_text: Vec::from_hex(ser.cipher_text).unwrap(),
            cipher_params: ser.cipher_params,
            kdf_params: ser.kdf_params,
            mac: ser.mac,
        }
    }
}

impl Into<SerCoreCrypto> for CoreCrypto {
    fn into(self) -> SerCoreCrypto {
        SerCoreCrypto {
            cipher: self.cipher,
            cipher_text: self.cipher_text.to_hex(),
            cipher_params: self.cipher_params,
            kdf: self.kdf_params.kdf.to_string(),
            kdf_params: self.kdf_params,
            mac: self.mac,
        }
    }
}

impl<'de> Deserialize<'de> for CoreCrypto {
    fn deserialize<D>(deserializer: D) -> Result<CoreCrypto, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ser: SerCoreCrypto = SerCoreCrypto::deserialize(deserializer)?;
        Ok(ser.into())
    }
}

impl Serialize for CoreCrypto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ser: SerCoreCrypto = self.clone().into();
        ser.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystore::{Kdf, Prf};
    use tests::*;

    const KDF_PARAMS_PBKDF2: &'static str = r#"{
        "c": 10240,
        "dklen": 32,
        "prf": "hmac-sha256",
        "salt": "095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b"
    }"#;

    const PBKDF2_TEXT: &'static str = r#"{
      "cipher": "aes-128-ctr",
      "cipherparams": {
        "iv": "58d54158c3e27131b0a0f2b91201aedc"
      },
      "ciphertext": "9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126",
      "kdf": "pbkdf2",
      "kdfparams": {
        "c": 10240,
        "dklen": 32,
        "prf": "hmac-sha256",
        "salt": "095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b"
      },
      "mac": "83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63"
    }"#;

    const SCRYPT_TEXT: &'static str = r#"{
      "ciphertext": "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1",
      "cipherparams": {
        "iv": "9df1649dd1c50f2153917e3b9e7164e9"
      },
      "cipher": "aes-128-ctr",
      "kdf": "scrypt",
      "kdfparams": {
        "dklen": 32,
        "salt": "fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4",
        "n": 1024,
        "r": 8,
        "p": 1
      },
      "mac": "9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5"
    }"#;

    #[test]
    fn should_serialize_kdf_params() {
        let exp = KdfParams {
            kdf: Kdf::Pbkdf2 {
                prf: Prf::default(),
                c: 10240,
            },
            dklen: 32,
            salt: serde_json::from_str(
                "\"095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b\"",
            ).unwrap(),
        };

        let mut act: KdfParams = serde_json::from_str(KDF_PARAMS_PBKDF2).unwrap();
        act = serde_json::from_str::<KdfParams>(&serde_json::to_string(&act).unwrap()).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_serialize_pbkdf2_crypto() {
        let exp = CoreCrypto {
            cipher: Cipher::default(),
            cipher_text: Vec::from_hex(
                "9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126",
            ).unwrap(),
            cipher_params: CipherParams {
                iv: serde_json::from_str("\"58d54158c3e27131b0a0f2b91201aedc\"").unwrap(),
            },
            kdf_params: KdfParams {
                kdf: Kdf::Pbkdf2 {
                    prf: Prf::default(),
                    c: 10240,
                },
                dklen: 32,
                salt: serde_json::from_str(
                    "\"095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b\"",
                ).unwrap(),
            },
            mac: serde_json::from_str(
                "\"83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63\"",
            ).unwrap(),
        };

        // just first encoding
        let mut act = serde_json::from_str::<CoreCrypto>(PBKDF2_TEXT).unwrap();
        act = serde_json::from_str::<CoreCrypto>(&serde_json::to_string(&act).unwrap()).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_serialize_scrypt_crypto() {
        let exp = CoreCrypto {
            cipher: Cipher::default(),
            cipher_text: Vec::from_hex(
                "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1",
            ).unwrap(),
            cipher_params: CipherParams {
                iv: serde_json::from_str("\"9df1649dd1c50f2153917e3b9e7164e9\"").unwrap(),
            },
            kdf_params: KdfParams {
                kdf: Kdf::Scrypt {
                    n: 1024,
                    r: 8,
                    p: 1,
                },
                dklen: 32,
                salt: serde_json::from_str(
                    "\"fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4\"",
                ).unwrap(),
            },
            mac: serde_json::from_str(
                "\"9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5\"",
            ).unwrap(),
        };

        // just first encoding
        let act = serde_json::from_str::<CoreCrypto>(SCRYPT_TEXT).unwrap();

        // verify encoding & decoding full cycle logic
        let act =
            serde_json::from_str::<CoreCrypto>(&serde_json::to_string(&act).unwrap()).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_not_decode_unknown_kdf_prf() {
        let text = PBKDF2_TEXT.replace(&Prf::default().to_string(), "unknown");

        assert!(serde_json::from_str::<CoreCrypto>(&text).is_err());
    }

    #[test]
    fn should_not_decode_unknown_cipher() {
        let text = SCRYPT_TEXT.replace(&Cipher::default().to_string(), "unknown");

        assert!(serde_json::from_str::<CoreCrypto>(&text).is_err());
    }

    #[test]
    fn should_not_decode_not_wrong_crypto() {
        assert!(serde_json::from_str::<CoreCrypto>("garbage").is_err());
    }
}
