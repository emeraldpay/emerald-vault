use crate::{
    convert::error::ConversionError,
    structs::crypto::{
        Aes128CtrCipher,
        Cipher,
        Encrypted,
        Kdf,
        MacType,
        Pbkdf2,
        PrfType,
        ScryptKdf,
    },
    EthereumAddress,
};
use std::convert::TryFrom;
use uuid::Uuid;

/// Keccak-256 crypto hash length in bytes
const KECCAK256_BYTES: usize = 32;
/// Key derivation function salt length in bytes
const KDF_SALT_BYTES: usize = 32;
/// Cipher initialization vector length in bytes
const CIPHER_IV_BYTES: usize = 16;

byte_array_struct!(
    pub struct Mac(KECCAK256_BYTES);
);
byte_array_struct!(
    pub struct Iv(CIPHER_IV_BYTES);
);
byte_array_struct!(
    pub struct Salt(KDF_SALT_BYTES);
);


/// A keystore file (entry private key encrypted with a passphrase)
#[derive(Deserialize, Debug, Clone)]
pub struct KeyFileV2 {
    /// Specifies if `Keyfile` is visible
    pub visible: Option<bool>,

    /// User specified name
    pub name: Option<String>,

    /// User specified description
    pub description: Option<String>,

    /// Address
    pub address: Option<EthereumAddress>,

    /// UUID v4
    pub uuid: Uuid,

    ///
    pub crypto: CryptoTypeV2,
}

/// A serializable keystore file (UTC / JSON format)
#[derive(Deserialize, Clone, Debug)]
pub struct SerializableKeyFileCoreV2 {
    version: u8,
    id: Uuid,
    address: Option<EthereumAddress>,
    name: Option<String>,
    description: Option<String>,
    visible: Option<bool>,
    crypto: CoreCryptoV2,
}

/// A serializable keystore file (UTC / JSON format)
#[derive(Deserialize, Clone, Debug)]
pub struct SerializableKeyFileHDV2 {
    version: u8,
    id: Uuid,
    address: Option<EthereumAddress>,
    name: Option<String>,
    description: Option<String>,
    visible: Option<bool>,
    crypto: HdwalletCryptoV2,
}

/// Variants of `crypto` section in `Keyfile`
///
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum CryptoTypeV2 {
    /// normal Web3 Secret Storage
    Core(CoreCryptoV2),

    /// backed with HD Wallet
    HdWallet(HdwalletCryptoV2),
}

/// `Keyfile` related crypto attributes
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CoreCryptoV2 {
    /// Cipher
    pub cipher: CipherV2,

    /// Cipher text
    #[serde(rename = "ciphertext")]
    pub cipher_text: String,

    /// Params for `Cipher`
    #[serde(rename = "cipherparams")]
    pub cipher_params: CipherParamsV2,

    /// Key derivation funciton
    #[serde(rename = "kdfparams")]
    pub kdf_params: KdfParamsV2,

    /// HMAC authentication code
    pub mac: Mac,
}

/// Cipher type
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherV2 {
    /// AES-CTR (specified in (RFC 3686)[https://tools.ietf.org/html/rfc3686])
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CipherParamsV2 {
    pub iv: Iv,
}

/// Key derivation function parameters
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParamsV2 {
    /// Key derivation function
    #[serde(flatten)]
    pub kdf: KdfV2,

    /// `Kdf` length for parameters
    pub dklen: usize,

    /// Cryptographic salt for `Kdf`
    pub salt: Salt,
}

/// Key derivation function
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum KdfV2 {
    /// PBKDF2 (not recommended, specified in (RFC 2898)[https://tools.ietf.org/html/rfc2898])
    #[serde(rename = "pbkdf2")]
    Pbkdf2 {
        /// Pseudo-Random Functions (`HMAC-SHA-256` by default)
        prf: PrfV2,

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

/// Pseudo-Random Functions (PRFs)
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrfV2 {
    /// HMAC-SHA-256 (specified in (RFC 4868)[https://tools.ietf.org/html/rfc4868])
    #[serde(rename = "hmac-sha256")]
    HmacSha256,

    /// HMAC-SHA-512 (specified in (RFC 4868)[https://tools.ietf.org/html/rfc4868])
    #[serde(rename = "hmac-sha512")]
    HmacSha512,
}

/// `Keyfile` for HD Wallet
#[derive(Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct HdwalletCryptoV2 {
    /// Cipher type 'hardware'
    pub cipher: String,

    /// HD Wallet type
    pub hardware: String,

    /// HD path as specified in BIP-32
    pub hd_path: String,
}

#[derive(Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct AddressBookItem {
    pub address: EthereumAddress,
    pub name: Option<String>,
    pub description: Option<String>,
}

// ---

impl TryFrom<&CoreCryptoV2> for Encrypted {
    type Error = ConversionError;

    fn try_from(value: &CoreCryptoV2) -> Result<Self, Self::Error> {
        let iv: [u8; CIPHER_IV_BYTES] = value.cipher_params.iv.clone().into();
        let mac: [u8; KECCAK256_BYTES] = value.mac.clone().into();
        let cipher = Cipher::Aes128Ctr(Aes128CtrCipher {
            encrypted: hex::decode(value.cipher_text.clone())
                .map_err(|_| ConversionError::InvalidJson)?,
            iv: iv.to_vec(),
            mac: MacType::Web3(mac.to_vec()),
        });
        let kdf = Kdf::from(value);
        let result = Encrypted { cipher, kdf, global_key: None };
        Ok(result)
    }
}

impl From<&CoreCryptoV2> for Kdf {
    fn from(crypto: &CoreCryptoV2) -> Self {
        match crypto.kdf_params.kdf {
            KdfV2::Pbkdf2 { prf, c } => {
                let prf = match prf {
                    PrfV2::HmacSha256 => PrfType::HmacSha256,
                    PrfV2::HmacSha512 => PrfType::HmacSha512,
                };
                Kdf::Pbkdf2(Pbkdf2 {
                    dklen: crypto.kdf_params.dklen as u32,
                    c,
                    salt: crypto.kdf_params.salt.clone().to_vec(),
                    prf,
                })
            }
            KdfV2::Scrypt { n, r, p } => Kdf::Scrypt(ScryptKdf {
                dklen: crypto.kdf_params.dklen as u32,
                salt: crypto.kdf_params.salt.clone().to_vec(),
                n,
                r,
                p,
            }),
        }
    }
}

impl Into<KeyFileV2> for SerializableKeyFileCoreV2 {
    fn into(self) -> KeyFileV2 {
        KeyFileV2 {
            name: self.name,
            description: self.description,
            address: self.address,
            visible: self.visible,
            uuid: self.id,
            crypto: CryptoTypeV2::Core(self.crypto),
        }
    }
}

impl Into<KeyFileV2> for SerializableKeyFileHDV2 {
    fn into(self) -> KeyFileV2 {
        KeyFileV2 {
            name: self.name,
            description: self.description,
            address: self.address,
            visible: self.visible,
            uuid: self.id,
            crypto: CryptoTypeV2::HdWallet(self.crypto),
        }
    }
}

impl KeyFileV2 {
    /// Decode `KeyfileV2` from JSON
    /// Handles different variants of `crypto` section
    ///
    pub fn decode(f: &str) -> Result<KeyFileV2, String> {
        let buf = f.to_string().to_lowercase();
        let mut ver = 0;

        let kf = serde_json::from_str::<SerializableKeyFileCoreV2>(&buf)
            .and_then(|core| {
                ver = core.version;
                Ok(core.into())
            })
            .or_else(|_| {
                serde_json::from_str::<SerializableKeyFileHDV2>(&buf).and_then(|hd| {
                    ver = hd.version;
                    Ok(hd.into())
                })
            })
            .map_err(|e| format!("Failed to deserialize JSON {:?} for {}", e, buf))?;

        Ok(kf)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        migration::source::json_data::{AddressBookItem, CryptoTypeV2, KeyFileV2},
        EthereumAddress,
    };
    use std::str::FromStr;

    #[test]
    fn parse_addressbook_json() {
        let json = r#"
        {
          "address": "0xB3c9A2f3F96ffBC4b7DEd2D92C83175698147Ae2",
          "description": "тест",
          "name": "name 1"
        }
        "#;

        let act = serde_json::from_slice::<AddressBookItem>(json.as_bytes());
        println!("{:?}", act);
        assert!(act.is_ok());
        let act = act.unwrap();
        assert_eq!(
            AddressBookItem {
                address: EthereumAddress::from_str("0xB3c9A2f3F96ffBC4b7DEd2D92C83175698147Ae2")
                    .unwrap(),
                description: Some("тест".to_string()),
                name: Some("name 1".to_string()),
            },
            act
        );
    }

    #[test]
    fn parse_keyfile() {
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

        let kf = KeyFileV2::decode(json);
        assert!(kf.is_ok());
        let kf = kf.unwrap();
        let cyphertext = match kf.crypto {
            CryptoTypeV2::Core(x) => x.cipher_text,
            _ => "not_core".to_string(),
        };
        assert_eq!(
            "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46".to_string(),
            cyphertext
        );
    }

    #[test]
    fn parse_keyfile_ledger() {
        let json = r#"
            {
                "version":3,
                "id": "f37f1640-d34f-4202-bbca-c11139b7ab7e",
                "address": "bd5222391bbb9f17484f2565455fb6610d9e145f",
                "name": "ledger m/44'/60'/0'/0",
                "description": null,
                "visible": null,
                "crypto": {
                    "cipher": "hardware",
                    "hardware": "ledger-nano-s:v1",
                    "hd_path":"m/44'/60'/0'/0"
                }
            }
        "#;

        let kf = KeyFileV2::decode(json);
        assert!(kf.is_ok());
        let kf = kf.unwrap();
        let hd_path = match kf.crypto {
            CryptoTypeV2::HdWallet(hw) => hw.hd_path,
            _ => "not_hd".to_string(),
        };
        assert_eq!("m/44'/60'/0'/0".to_string(), hd_path);
    }
}
