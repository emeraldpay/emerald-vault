use hmac::Hmac;
use pbkdf2::pbkdf2;
use scrypt::{scrypt, ScryptParams};
use sha2::{Sha256, Sha512};
use std::convert::{TryFrom, TryInto};
use crate::proto::crypto::{
    Encrypted as proto_Encrypted,
    Encrypted_CipherType as proto_CipherType,
    Encrypted_oneof_kdf_type as proto_Encrypted_oneof_kdf_type,
    PrfType as proto_PrfType,
    ScryptKdf as proto_ScryptKdf,
    Pbkdf2 as proto_Pbkdf2,
    Mac as proto_Mac,
    Mac_MacType as proto_MacType
};
use crate::storage::error::VaultError;
use crate::convert::ethereum::EthereumJsonV3File;
use crate::convert::proto::types::IsVerified;
use crate::keystore::{
    Salt as ks_Salt,
    Kdf as ks_Kdf,
    Prf as ks_Prf,
    KdfParams as ks_KdfParams,
    CoreCrypto as ks_CoreCrypto,
    Cipher as ks_Cipher,
    Mac as ks_Mac,
    serialize::{
        crypto::CipherParams as ks_CipherParams,
        Iv as ks_Iv
    },
};

pub struct ScryptKdf {
    pub dklen: u32,
    pub salt: Vec<u8>,
    pub n: u32,
    pub r: u32,
    pub p: u32
}

pub struct Pbkdf2 {
    pub dklen: u32,
    pub c: u32,
    pub salt: Vec<u8>,
    pub prf: PrfType
}

pub enum PrfType {
    HmacSha256,
    HmacSha512
}

pub enum Kdf {
    Scrypt(ScryptKdf),
    Pbkdf2(Pbkdf2)
}

pub struct Encrypted {
    pub cipher: Cipher,
    pub kdf: Kdf
}

pub enum Cipher {
    Aes128Ctr(Aes128CtrCipher)
}

pub struct Aes128CtrCipher {
    pub encrypted: Vec<u8>,
    pub iv: Vec<u8>,
    pub mac: MacType,
}

pub enum MacType {
    Web3(Vec<u8>)
}

enum CryptoError {
    InvalidData
}

impl Encrypted {

    pub fn get_mac(&self) -> &Vec<u8> {
        match &self.cipher {
            Cipher::Aes128Ctr(v) => match &v.mac {
                MacType::Web3(x) => x
            }
        }
    }

    pub fn get_iv(&self) -> &Vec<u8> {
        match &self.cipher {
            Cipher::Aes128Ctr(v) => &v.iv
        }
    }

    pub fn get_message(&self) -> &Vec<u8> {
        match &self.cipher {
            Cipher::Aes128Ctr(v) => &v.encrypted
        }
    }

}

impl IsVerified for ScryptKdf {
    fn verify(self) -> Result<Self, String> {
        if self.salt.len() != 32 {
            return Err("salt has invalid size".to_string())
        }
        if self.dklen != 32 {
            return Err("dklen has invalid value".to_string())
        }
        if self.p <= 0 {
            return Err("p is too small".to_string())
        }
        if self.n <= 0 {
            return Err("n is too small".to_string())
        }
        if self.r <= 0 {
            return Err("r is too small".to_string())
        }
        Ok(self)
    }
}

/// From Protobuf Message
impl TryFrom<proto_PrfType> for PrfType {
    type Error = VaultError;
    fn try_from(data: proto_PrfType) -> Result<Self, VaultError> where Self: std::marker::Sized {
        match data {
            proto_PrfType::PRF_HMAC_SHA256 => Ok(PrfType::HmacSha256),
            proto_PrfType::PRF_UNKNOWN => Err(VaultError::UnsupportedDataError("HMAC type is not set".to_string()))
        }
    }
}

impl TryFrom<&proto_Mac> for MacType {
    type Error = VaultError;

    fn try_from(value: &proto_Mac) -> Result<Self, Self::Error> {
        match value.field_type {
            proto_MacType::MAC_WEB3 => Ok(MacType::Web3(value.value.clone())),
            proto_MacType::MAC_UNKNOWN => Err(VaultError::UnsupportedDataError("MAC type is not set".to_string()))
        }
    }
}

/// From Protobuf Message
impl TryFrom<&proto_Encrypted> for Cipher {
    type Error = VaultError;
    fn try_from(data: &proto_Encrypted) -> Result<Self, VaultError> where Self: std::marker::Sized {
        match &data.field_type {
            proto_CipherType::CIPHER_AES128_CTR => Ok(
                Cipher::Aes128Ctr(
                    Aes128CtrCipher {
                        encrypted: data.secret.clone(),
                        iv: data.iv.clone(),
                        mac: match data.mac.as_ref() {
                            Some(mac) => MacType::try_from(mac),
                            None => Err(VaultError::InvalidDataError("MAC is not set".to_string()))
                        }?
                    }
                )
            ),
            proto_CipherType::CIPHER_UNKNOWN => Err(
                VaultError::UnsupportedDataError("Cipher type is not set".to_string())
            )
        }
    }
}

/// From Protobuf Message
impl TryFrom<&proto_Encrypted_oneof_kdf_type> for Kdf {
    type Error = VaultError;
    fn try_from(data: &proto_Encrypted_oneof_kdf_type) -> Result<Self, VaultError> where Self: std::marker::Sized {
        match data {
            proto_Encrypted_oneof_kdf_type::kdf_scrypt(value) => Ok(
                Kdf::Scrypt(ScryptKdf{
                    dklen: value.dklen,
                    salt: value.salt.clone(),
                    n: value.n,
                    r: value.r,
                    p: value.p
                }.verify()?)
            ),
            proto_Encrypted_oneof_kdf_type::kdf_pbkdf(value) => Ok(
                Kdf::Pbkdf2(Pbkdf2 {
                    dklen: value.dklen,
                    c: value.c,
                    salt: value.salt.clone(),
                    prf: PrfType::try_from(value.prf)?
                })
            )
        }
    }
}

/// To Protobuf Message
impl From<&ScryptKdf> for proto_ScryptKdf {
    fn from(value: &ScryptKdf) -> Self {
        let mut result = proto_ScryptKdf::new();
        result.set_dklen(value.dklen);
        result.set_salt(value.salt.clone());
        result.set_n(value.n);
        result.set_p(value.p);
        result.set_r(value.r);
        result
    }
}

/// To Protobuf Message
impl TryFrom<&Pbkdf2> for proto_Pbkdf2 {
    type Error = VaultError;
    fn try_from(value: &Pbkdf2) -> Result<Self, VaultError> {
        let mut result = proto_Pbkdf2::new();
        result.set_dklen(value.dklen);
        result.set_salt(value.salt.clone());
        result.set_c(value.c);
        match value.prf {
            PrfType::HmacSha256 => {
                result.set_prf(proto_PrfType::PRF_HMAC_SHA256)
            },
            PrfType::HmacSha512 => {
                return Err(VaultError::UnsupportedDataError("HMAC-SHA512 is not supported".to_string()))
            },
        }
        Ok(result)
    }
}


/// From Protobuf Message
impl TryFrom<&proto_Encrypted> for Encrypted {
    type Error = VaultError;
    fn try_from(data: &proto_Encrypted) -> Result<Self, VaultError> where Self: std::marker::Sized {
        let cipher = Cipher::try_from(data)?;
        let kdf = match &data.kdf_type {
            Some(kdf_type) => Kdf::try_from(kdf_type),
            None => Err(VaultError::InvalidDataError("KDF is not specified".to_string()))
        }?;
        Ok(Encrypted { cipher, kdf })
    }
}

/// To Protobuf Message
impl TryFrom<&Encrypted> for proto_Encrypted {
    type Error = VaultError;

    fn try_from(value: &Encrypted) -> Result<Self, Self::Error> {
        let mut encrypted = proto_Encrypted::new();
        encrypted.set_iv(value.get_iv().clone());
        encrypted.set_secret(value.get_message().clone());
        match &value.kdf {
            Kdf::Scrypt(x) => {
                encrypted.set_kdf_scrypt(proto_ScryptKdf::from(x))
            },
            Kdf::Pbkdf2(x) => {
                encrypted.set_kdf_pbkdf(proto_Pbkdf2::try_from(x)?)
            }
        }
        match &value.cipher {
            Cipher::Aes128Ctr(x) => {
                encrypted.set_field_type(proto_CipherType::CIPHER_AES128_CTR);
                match &x.mac {
                    MacType::Web3(mac_value) => {
                        let mut mac = proto_Mac::new();
                        mac.set_field_type(proto_MacType::MAC_WEB3);
                        mac.set_value(mac_value.clone());
                        encrypted.set_mac(mac);
                    }
                }
            }
        }

        Ok(encrypted)
    }
}

impl From<&EthereumJsonV3File> for Encrypted {
    fn from(json: &EthereumJsonV3File) -> Self {
        let cipher = Cipher::Aes128Ctr(
            Aes128CtrCipher {
                encrypted: json.crypto.cipher_text.clone(),
                iv: json.crypto.cipher_params.iv.clone().to_vec(),
                mac: MacType::Web3(json.crypto.mac.clone().to_vec())
            }
        );
        let kdf = match json.crypto.kdf_params.kdf {
            ks_Kdf::Pbkdf2 { prf, c } => {
                let prf = match prf {
                    ks_Prf::HmacSha256 => PrfType::HmacSha256,
                    ks_Prf::HmacSha512 => PrfType::HmacSha512
                };
                Kdf::Pbkdf2(Pbkdf2 {
                    dklen: json.crypto.kdf_params.dklen as u32,
                    c,
                    salt: json.crypto.kdf_params.salt.clone().to_vec(),
                    prf
                })
            },
            ks_Kdf::Scrypt { n, r, p } => {
                Kdf::Scrypt(ScryptKdf {
                    dklen: json.crypto.kdf_params.dklen as u32,
                    salt: json.crypto.kdf_params.salt.clone().to_vec(),
                    n,
                    r,
                    p
                })
            },
        };
        Encrypted { cipher, kdf }
    }
}


impl TryFrom<&Encrypted> for ks_CoreCrypto {
    type Error = VaultError;

    fn try_from(value: &Encrypted) -> Result<Self, Self::Error> {
        match &value.cipher {
            Cipher::Aes128Ctr(cipher) => {
                let kdf = match &value.kdf {
                    Kdf::Pbkdf2(value) => ks_Kdf::Pbkdf2 {
                        prf: match value.prf {
                            PrfType::HmacSha256 => ks_Prf::HmacSha256,
                            PrfType::HmacSha512 => ks_Prf::HmacSha512,
                        },
                        c: value.c
                    },
                    Kdf::Scrypt(value) => ks_Kdf::Scrypt {
                        n: value.n,
                        r: value.r,
                        p: value.p
                    }
                };
                let mac = match &cipher.mac {
                    MacType::Web3(v) => v.clone()
                };
                let result = ks_CoreCrypto {
                    cipher: ks_Cipher::Aes128Ctr,
                    cipher_text: cipher.encrypted.clone(),
                    cipher_params: ks_CipherParams {
                        iv: cipher.iv.clone().try_into()?
                    },
                    kdf_params: ks_KdfParams {
                        kdf,
                        dklen: 32,
                        salt: match &value.kdf {
                            Kdf::Pbkdf2(v) => v.salt.clone(),
                            Kdf::Scrypt(v) => v.salt.clone()
                        }.try_into()?
                    },
                    mac: mac.try_into()?
                };
                Ok(result)
            }
        }
    }
}
