use uuid::Uuid;
use std::convert::{TryInto, TryFrom};
use crate::keystore::{CoreCrypto, Kdf as ks_Kdf, Prf as ks_Prf, CIPHER_IV_BYTES};
use crate::convert::proto::{
    crypto::{Encrypted, Cipher, Aes128CtrCipher, Kdf, Pbkdf2, PrfType, ScryptKdf, MacType},
    pk::{PrivateKeyHolder, EthereumPk3, PrivateKeyType},
    wallet::{Wallet},
    types::{HasUuid}
};
use crate::core::Address;
use crate::util::KECCAK256_BYTES;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ConversionError {
    InvalidArgument,
    InvalidJson,
    UnsuportedVersion
}

impl From<serde_json::Error> for ConversionError {
    fn from(_: serde_json::Error) -> Self {
        ConversionError::InvalidJson
    }
}

pub struct EthereumJsonV3 {}

// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EthereumJsonV3File {
    pub id: Uuid,
    pub version: u32,
    pub address: Option<Address>,
    pub crypto: CoreCrypto,
    pub name: Option<String>,
    pub description: Option<String>
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

impl TryFrom<&CoreCrypto> for Encrypted {
    type Error = ConversionError;

    fn try_from(value: &CoreCrypto) -> Result<Self, Self::Error> {
        let iv: [u8; CIPHER_IV_BYTES] = value.cipher_params.iv.clone().into();
        let mac: [u8; KECCAK256_BYTES] = value.mac.clone().into();
        let cipher = Cipher::Aes128Ctr(
            Aes128CtrCipher {
                encrypted: value.cipher_text.clone(),
                iv: iv.to_vec(),
                mac: MacType::Web3(mac.to_vec())
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
        let pk = PrivateKeyType::Ethereum(pk3);
        let result = PrivateKeyHolder {
            id: value.id,
            pk
        };
        Ok(result)
    }
}

// DELETE
impl From<&CoreCrypto> for Kdf {
    fn from(crypto: &CoreCrypto) -> Self {
        match crypto.kdf_params.kdf {
            ks_Kdf::Pbkdf2 {prf, c} => {
                let prf = match prf {
                    ks_Prf::HmacSha256 => PrfType::HmacSha256,
                    ks_Prf::HmacSha512 => PrfType::HmacSha512
                };
                Kdf::Pbkdf2(
                    Pbkdf2 {
                        dklen: crypto.kdf_params.dklen as u32,
                        c,
                        salt: crypto.kdf_params.salt.clone().to_vec(),
                        prf
                    }
                )
            },
            ks_Kdf::Scrypt {n, r, p} => {
                Kdf::Scrypt(
                    ScryptKdf {
                        dklen: crypto.kdf_params.dklen as u32,
                        salt: crypto.kdf_params.salt.clone().to_vec(),
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
            PrivateKeyType::Ethereum(pk3) => {
                let crypto = CoreCrypto::try_from(&pk3.key);
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
    use crate::keystore::{CoreCrypto, Kdf as ks_Kdf, Prf as ks_Prf, CIPHER_IV_BYTES};
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

        let parsed = EthereumJsonV3File::try_from(json.to_string()).expect("Not parsed");
        assert_eq!("6087dab2f9fdbbfaddc31a909735c1e6", hex::encode(parsed.crypto.cipher_params.iv.into_bytes()));
        assert_eq!("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46", hex::encode(parsed.crypto.cipher_text));
        assert_eq!(ks_Kdf::Pbkdf2 { prf: ks_Prf::HmacSha256, c: 262144}, parsed.crypto.kdf_params.kdf);
        assert_eq!(32, parsed.crypto.kdf_params.dklen);
        assert_eq!("ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd", hex::encode(parsed.crypto.kdf_params.salt.into_bytes()));
        assert_eq!("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2", hex::encode(parsed.crypto.mac.into_bytes()));
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
        assert_eq!("83dbcc02d8ccb40e466191a123791e0e", hex::encode(parsed.crypto.cipher_params.iv.into_bytes()));
        assert_eq!("d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c", hex::encode(parsed.crypto.cipher_text));
        assert_eq!(ks_Kdf::Scrypt { n: 262144, r: 1, p: 8 }, parsed.crypto.kdf_params.kdf);
        assert_eq!(32, parsed.crypto.kdf_params.dklen);
        assert_eq!("ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19", hex::encode(parsed.crypto.kdf_params.salt.into_bytes()));
        assert_eq!("2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097", hex::encode(parsed.crypto.mac.into_bytes()));
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
        assert_eq!("e4610fb26bd43fa17d1f5df7a415f084", hex::encode(parsed.crypto.cipher_params.iv.into_bytes()));
        assert_eq!("dc50ab7bf07c2a793206683397fb15e5da0295cf89396169273c3f49093e8863", hex::encode(parsed.crypto.cipher_text));
        assert_eq!(ks_Kdf::Scrypt { n: 1024, r: 8, p: 1 }, parsed.crypto.kdf_params.kdf);
        assert_eq!(32, parsed.crypto.kdf_params.dklen);
        assert_eq!("86c6a8857563b57be9e16ad7a3f3714f80b714bcf9da32a2788d695a194f3275", hex::encode(parsed.crypto.kdf_params.salt.into_bytes()));
        assert_eq!("8dfedc1a92e2f2ca1c0c60cd40fabb8fb6ce7c05faf056281eb03e0a9996ecb0", hex::encode(parsed.crypto.mac.into_bytes()));
        assert_eq!("305f4853-80af-4fa6-8619-6f285e83cf28", parsed.id.to_string());
        assert!(parsed.address.is_some());
        assert_eq!("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99", parsed.address.unwrap().to_string());
        assert_eq!(Some("Hello".to_string()), parsed.name);
        assert_eq!(Some("World!!!!".to_string()), parsed.description);
    }
}
