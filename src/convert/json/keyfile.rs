use uuid::Uuid;
use std::convert::{TryInto, TryFrom};
use std::fmt;
use std::str::FromStr;
use crate::{
    convert::{
        error::ConversionError,
        proto::{
            crypto::{Encrypted, Cipher, Aes128CtrCipher, Kdf, Pbkdf2, PrfType, ScryptKdf, MacType},
            pk::{PrivateKeyHolder, EthereumPk3, PrivateKeyType},
            wallet::{Wallet},
            types::{HasUuid},
        },
    },
    core::Address,
    storage::error::VaultError,
    util::KECCAK256_BYTES,
    Error,
};
use serde::{Deserialize, Deserializer};

/// `PBKDF2` key derivation function name
pub const PBKDF2_KDF_NAME: &str = "pbkdf2";
/// `Scrypt` key derivation function name
pub const SCRYPT_KDF_NAME: &str = "scrypt";
/// Derived core length in bytes (by default)
pub const DEFAULT_DK_LENGTH: usize = 32;
/// `HMAC_SHA256` pseudo-random function name
pub const HMAC_SHA256_PRF_NAME: &str = "hmac-sha256";
/// `HMAC_SHA512` pseudo-random function name
pub const HMAC_SHA512_PRF_NAME: &str = "hmac-sha512";
/// Key derivation function salt length in bytes
pub const KDF_SALT_BYTES: usize = 32;
/// Cipher initialization vector length in bytes
pub const CIPHER_IV_BYTES: usize = 16;

type HexString = String;

// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EthereumJsonV3File {
    pub id: Uuid, // maybe just any string
    pub version: u32,
    pub address: Option<Address>,
    pub crypto: CoreCryptoJson,
    pub name: Option<String>,
    pub description: Option<String>
}

/// `Keyfile` related crypto attributes
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct CoreCryptoJson {
    /// Cipher
    pub cipher: CipherId,

    /// Cipher text
    #[serde(rename = "ciphertext")]
    pub cipher_text: HexString,

    /// Params for `Cipher`
    #[serde(rename = "cipherparams")]
    pub cipher_params: CipherParamsJson,

    /// Key derivation funciton
    #[serde(rename = "kdfparams")]
    pub kdf_params: KdfParamsJson,

    /// HMAC authentication code
    pub mac: HexString,
}

impl Default for CoreCryptoJson {
    fn default() -> Self {
        Self {
            cipher: CipherId::default(),
            cipher_text: "".to_string(),
            cipher_params: CipherParamsJson::default(),
            kdf_params: KdfParamsJson::default(),
            mac: "".to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum CipherId {
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr
}

impl Default for CipherId {
    fn default() -> Self {
        CipherId::Aes128Ctr
    }
}

impl ToString for CipherId {
    fn to_string(&self) -> String {
        match self {
            CipherId::Aes128Ctr => "aes-128-ctr".to_string()
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CipherParamsJson {
    pub iv: HexString,
}

impl Default for CipherParamsJson {
    fn default() -> Self {
        CipherParamsJson {
            iv: "".to_string(),
        }
    }
}

/// Key derivation function parameters
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KdfParamsJson {
    /// Key derivation function
    #[serde(flatten)]
    pub kdf: KdfJson,

    /// `Kdf` length for parameters
    pub dklen: usize,

    /// Cryptographic salt for `Kdf`
    pub salt: HexString,
}

impl Default for KdfParamsJson {
    fn default() -> Self {
        Self {
            kdf: KdfJson::default(),
            dklen: DEFAULT_DK_LENGTH,
            salt: "".to_string(),
        }
    }
}

/// Pseudo-Random Functions (PRFs)
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrfJson {
    /// HMAC-SHA-256 (specified in (RFC 4868)[https://tools.ietf.org/html/rfc4868])
    #[serde(rename = "hmac-sha256")]
    HmacSha256,

    /// HMAC-SHA-512 (specified in (RFC 4868)[https://tools.ietf.org/html/rfc4868])
    #[serde(rename = "hmac-sha512")]
    HmacSha512,
}


impl Default for PrfJson {
    fn default() -> Self {
        PrfJson::HmacSha256
    }
}

impl FromStr for PrfJson {
    type Err = ConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == HMAC_SHA256_PRF_NAME => Ok(PrfJson::HmacSha256),
            _ if s == HMAC_SHA512_PRF_NAME => Ok(PrfJson::HmacSha512),
            _ => Err(ConversionError::InvalidData("hmac".to_string())),
        }
    }
}

impl fmt::Display for PrfJson {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PrfJson::HmacSha256 => f.write_str(HMAC_SHA256_PRF_NAME),
            PrfJson::HmacSha512 => f.write_str(HMAC_SHA512_PRF_NAME),
        }
    }
}

/// Key derivation function
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum KdfJson {
    /// PBKDF2 (not recommended, specified in (RFC 2898)[https://tools.ietf.org/html/rfc2898])
    #[serde(rename = "pbkdf2")]
    Pbkdf2 {
        /// Pseudo-Random Functions (`HMAC-SHA-256` by default)
        prf: PrfJson,

        /// Number of iterations (`262144` by default)
        c: u32,
    },

    /// Scrypt (by default, specified in (RPC 7914)[https://tools.ietf.org/html/rfc7914])
    #[serde(rename = "scrypt")]
    Scrypt {
        /// Number of iterations (`19201` by default)
        n: u32,

        /// Block size for the underlying hash (`8` by default)
        r: u32,

        /// Parallelization factor (`1` by default)
        p: u32,
    },
}

impl Default for KdfJson {
    fn default() -> Self {
        KdfJson::Scrypt {
            n: 1024,
            r: 8,
            p: 1,
        }
    }
}

//impl From<KdfDepthLevel> for KdfJson {
//    fn from(sec: KdfDepthLevel) -> Self {
//        KdfJson::from((sec as u32, 8, 1))
//    }
//}

impl From<u32> for KdfJson {
    fn from(c: u32) -> Self {
        KdfJson::Pbkdf2 {
            prf: PrfJson::default(),
            c,
        }
    }
}

impl From<(u32, u32, u32)> for KdfJson {
    fn from(t: (u32, u32, u32)) -> Self {
        KdfJson::Scrypt {
            n: t.0,
            r: t.1,
            p: t.2,
        }
    }
}

impl FromStr for KdfJson {
    type Err = ConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == PBKDF2_KDF_NAME => Ok(KdfJson::Pbkdf2 {
                prf: PrfJson::default(),
                c: 262_144,
            }),
            _ if s == SCRYPT_KDF_NAME => Ok(KdfJson::default()),
            _ => Err(ConversionError::InvalidData(s.to_string())),
        }
    }
}

impl fmt::Display for KdfJson {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KdfJson::Pbkdf2 { .. } => f.write_str(PBKDF2_KDF_NAME),
            KdfJson::Scrypt { .. } => f.write_str(SCRYPT_KDF_NAME),
        }
    }
}

impl TryFrom<String> for EthereumJsonV3File {
    type Error = ConversionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parsed: EthereumJsonV3File = serde_json::from_str(value.as_str())?;
        if parsed.version != 3 {
            return Err(ConversionError::UnsuportedVersion)
        }
        Ok(parsed)
    }
}

impl TryFrom<&CoreCryptoJson> for Encrypted {
    type Error = ConversionError;

    fn try_from(value: &CoreCryptoJson) -> Result<Self, Self::Error> {
        let iv = hex::decode(value.cipher_params.iv.clone())?;
        let mac = hex::decode(value.mac.clone())?;
        let cipher = Cipher::Aes128Ctr(
            Aes128CtrCipher {
                encrypted: hex::decode(value.cipher_text.clone())?,
                iv,
                mac: MacType::Web3(mac)
            }
        );
        let kdf = Kdf::from(value);
        let result = Encrypted {
            cipher, kdf
        };
        Ok(result)
    }
}

impl TryFrom<&EthereumJsonV3File> for PrivateKeyHolder {
    type Error = ConversionError;

    fn try_from(value: &EthereumJsonV3File) -> Result<Self, Self::Error> {
        let pk3: EthereumPk3 = EthereumPk3 {
            address: value.address,
            key: Encrypted::try_from(&value.crypto)?
        };
        let pk = PrivateKeyType::EthereumPk(pk3);
        let result = PrivateKeyHolder {
            id: value.id,
            pk
        };
        Ok(result)
    }
}

// DELETE
impl From<&CoreCryptoJson> for Kdf {
    fn from(crypto: &CoreCryptoJson) -> Self {
        match crypto.kdf_params.kdf {
            KdfJson::Pbkdf2 {prf, c} => {
                let prf = match prf {
                    PrfJson::HmacSha256 => PrfType::HmacSha256,
                    PrfJson::HmacSha512 => PrfType::HmacSha512
                };
                Kdf::Pbkdf2(
                    Pbkdf2 {
                        dklen: crypto.kdf_params.dklen as u32,
                        c,
                        salt: hex::decode(crypto.kdf_params.salt.clone()).unwrap(),
                        prf
                    }
                )
            },
            KdfJson::Scrypt {n, r, p} => {
                Kdf::Scrypt(
                    ScryptKdf {
                        dklen: crypto.kdf_params.dklen as u32,
                        salt: hex::decode(crypto.kdf_params.salt.clone()).unwrap(),
                        n,
                        r,
                        p
                    }
                )
            }
        }
    }
}

impl EthereumJsonV3File {
    pub fn from_wallet(wallet: &Wallet, pk: &PrivateKeyHolder) -> Result<EthereumJsonV3File, ()> {
        let result = match &pk.pk {
            PrivateKeyType::EthereumPk(pk3) => {
                let crypto = CoreCryptoJson::try_from(&pk3.key);
                if crypto.is_err() {
                    return Err(())
                }
                EthereumJsonV3File {
                    id: wallet.get_id(),
                    version: 3,
                    address: pk3.address,
                    crypto: crypto.unwrap(),
                    name: wallet.label.clone(),
                    description: None
                }
            }
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use hex;
    use crate::util::KECCAK256_BYTES;
    use crate::convert::json::keyfile::{CoreCryptoJson, KdfJson, PrfJson};
    use hex::ToHex;

    #[test]
    fn import_pbkdf_default() {
        let json = r#"
            {
                "crypto" : {
                    "cipher" : "aes-128-ctr",
                    "cipherparams" : {
                        "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
                    },
                    "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
                    "kdf" : "pbkdf2",
                    "kdfparams" : {
                        "c" : 262144,
                        "dklen" : 32,
                        "prf" : "hmac-sha256",
                        "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                    },
                    "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
                },
                "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
                "version" : 3
            }
            "#;

        let parsed = EthereumJsonV3File::try_from(json.to_string()).unwrap();
        assert_eq!("6087dab2f9fdbbfaddc31a909735c1e6", parsed.crypto.cipher_params.iv);
        assert_eq!("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46", parsed.crypto.cipher_text);
        assert_eq!(KdfJson::Pbkdf2 { prf: PrfJson::HmacSha256, c: 262144}, parsed.crypto.kdf_params.kdf);
        assert_eq!(32, parsed.crypto.kdf_params.dklen);
        assert_eq!("ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd", parsed.crypto.kdf_params.salt);
        assert_eq!("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2", parsed.crypto.mac);
        assert_eq!("3198bc9c-6672-5ab3-d995-4942343ae5b6", parsed.id.to_string());
        assert_eq!(None, parsed.address);
    }

    #[test]
    fn import_scrypt_default() {
        let json = r#"
            {
                "crypto" : {
                    "cipher" : "aes-128-ctr",
                    "cipherparams" : {
                        "iv" : "83dbcc02d8ccb40e466191a123791e0e"
                    },
                    "ciphertext" : "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
                    "kdf" : "scrypt",
                    "kdfparams" : {
                        "dklen" : 32,
                        "n" : 262144,
                        "p" : 8,
                        "r" : 1,
                        "salt" : "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                    },
                    "mac" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
                },
                "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
                "version" : 3
            }
            "#;

        let parsed = EthereumJsonV3File::try_from(json.to_string()).expect("Not parsed");
        assert_eq!("83dbcc02d8ccb40e466191a123791e0e", parsed.crypto.cipher_params.iv);
        assert_eq!("d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c", parsed.crypto.cipher_text);
        assert_eq!(KdfJson::Scrypt { n: 262144, r: 1, p: 8 }, parsed.crypto.kdf_params.kdf);
        assert_eq!(32, parsed.crypto.kdf_params.dklen);
        assert_eq!("ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19", parsed.crypto.kdf_params.salt);
        assert_eq!("2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097", parsed.crypto.mac);
        assert_eq!("3198bc9c-6672-5ab3-d995-4942343ae5b6", parsed.id.to_string());
        assert_eq!(None, parsed.address);
    }

    #[test]
    fn import_with_address() {
        let json = r#"
            {
                "version": 3,
                "id": "305f4853-80af-4fa6-8619-6f285e83cf28",
                "address": "6412c428fc02902d137b60dc0bd0f6cd1255ea99",
                "name": "Hello",
                "description": "World!!!!",
                "visible": true,
                "crypto": {
                    "cipher": "aes-128-ctr",
                    "cipherparams": {"iv": "e4610fb26bd43fa17d1f5df7a415f084"},
                    "ciphertext": "dc50ab7bf07c2a793206683397fb15e5da0295cf89396169273c3f49093e8863",
                    "kdf": "scrypt",
                    "kdfparams": {
                        "dklen": 32,
                        "salt": "86c6a8857563b57be9e16ad7a3f3714f80b714bcf9da32a2788d695a194f3275",
                        "n": 1024,
                        "r": 8,
                        "p": 1
                    },
                    "mac": "8dfedc1a92e2f2ca1c0c60cd40fabb8fb6ce7c05faf056281eb03e0a9996ecb0"
                }
            }
        "#;

        let parsed = EthereumJsonV3File::try_from(json.to_string()).expect("Not parsed");
        assert_eq!("e4610fb26bd43fa17d1f5df7a415f084", parsed.crypto.cipher_params.iv);
        assert_eq!("dc50ab7bf07c2a793206683397fb15e5da0295cf89396169273c3f49093e8863", parsed.crypto.cipher_text);
        assert_eq!(KdfJson::Scrypt { n: 1024, r: 8, p: 1 }, parsed.crypto.kdf_params.kdf);
        assert_eq!(32, parsed.crypto.kdf_params.dklen);
        assert_eq!("86c6a8857563b57be9e16ad7a3f3714f80b714bcf9da32a2788d695a194f3275", parsed.crypto.kdf_params.salt);
        assert_eq!("8dfedc1a92e2f2ca1c0c60cd40fabb8fb6ce7c05faf056281eb03e0a9996ecb0", parsed.crypto.mac);
        assert_eq!("305f4853-80af-4fa6-8619-6f285e83cf28", parsed.id.to_string());
        assert!(parsed.address.is_some());
        assert_eq!("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99", parsed.address.unwrap().to_string());
        assert_eq!(Some("Hello".to_string()), parsed.name);
        assert_eq!(Some("World!!!!".to_string()), parsed.description);
    }

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
    fn should_deserialize_kdf_params() {
        let exp = KdfParamsJson {
            kdf: KdfJson::Pbkdf2 {
                prf: PrfJson::default(),
                c: 10240,
            },
            dklen: 32,
            salt: "095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b".to_string(),
        };

        let act: KdfParamsJson = serde_json::from_str(KDF_PARAMS_PBKDF2).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_deserialize_pbkdf2_crypto() {
        let exp = CoreCryptoJson {
            cipher: CipherId::default(),
            cipher_text: "9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126".to_string(),
            cipher_params: CipherParamsJson {
                iv: "58d54158c3e27131b0a0f2b91201aedc".to_string(),
            },
            kdf_params: KdfParamsJson {
                kdf: KdfJson::Pbkdf2 {
                    prf: PrfJson::default(),
                    c: 10240,
                },
                dklen: 32,
                salt: "095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b".to_string(),
            },
            mac: "83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63".to_string(),
        };

        // just first encoding
        let act = serde_json::from_str::<CoreCryptoJson>(PBKDF2_TEXT).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_deserialize_scrypt_crypto() {
        let exp = CoreCryptoJson {
            cipher: CipherId::default(),
            cipher_text: "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1".to_string(),
            cipher_params: CipherParamsJson {
                iv: "9df1649dd1c50f2153917e3b9e7164e9".to_string(),
            },
            kdf_params: KdfParamsJson {
                kdf: KdfJson::Scrypt {
                    n: 1024,
                    r: 8,
                    p: 1,
                },
                dklen: 32,
                salt: "fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4".to_string(),
            },
            mac: "9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5".to_string(),
        };

        // just first encoding
        let act = serde_json::from_str::<CoreCryptoJson>(SCRYPT_TEXT).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_not_decode_unknown_kdf_prf() {
        let text = PBKDF2_TEXT.replace(&PrfJson::default().to_string(), "unknown");

        assert!(serde_json::from_str::<CoreCryptoJson>(&text).is_err());
    }

    #[test]
    fn should_not_decode_unknown_cipher() {
        let text = SCRYPT_TEXT.replace(&CipherId::default().to_string(), "unknown");

        assert!(serde_json::from_str::<CoreCryptoJson>(&text).is_err());
    }

    #[test]
    fn should_not_decode_not_wrong_crypto() {
        assert!(serde_json::from_str::<CoreCryptoJson>("garbage").is_err());
    }
}

