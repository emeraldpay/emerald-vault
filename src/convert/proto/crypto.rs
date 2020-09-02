use crate::{
    convert::error::ConversionError,
    proto::crypto::{
        Encrypted as proto_Encrypted,
        Encrypted_CipherType as proto_CipherType,
        Encrypted_oneof_kdf_type as proto_Encrypted_oneof_kdf_type,
        Mac as proto_Mac,
        Mac_MacType as proto_MacType,
        Pbkdf2 as proto_Pbkdf2,
        PrfType as proto_PrfType,
        ScryptKdf as proto_ScryptKdf,
    },
    structs::{
        crypto::{Aes128CtrCipher, Cipher, Encrypted, Kdf, MacType, Pbkdf2, PrfType, ScryptKdf},
        types::IsVerified,
    },
};
use std::convert::TryFrom;

/// From Protobuf Message
impl TryFrom<proto_PrfType> for PrfType {
    type Error = ConversionError;
    fn try_from(data: proto_PrfType) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        match data {
            proto_PrfType::PRF_HMAC_SHA256 => Ok(PrfType::HmacSha256),
            proto_PrfType::PRF_UNKNOWN => {
                Err(ConversionError::FieldIsEmpty("prf_type".to_string()))
            }
        }
    }
}

impl TryFrom<&proto_Mac> for MacType {
    type Error = ConversionError;

    fn try_from(value: &proto_Mac) -> Result<Self, Self::Error> {
        match value.field_type {
            proto_MacType::MAC_WEB3 => Ok(MacType::Web3(value.value.clone())),
            proto_MacType::MAC_UNKNOWN => {
                Err(ConversionError::FieldIsEmpty("mac_type".to_string()))
            }
        }
    }
}

/// From Protobuf Message
impl TryFrom<&proto_Encrypted> for Cipher {
    type Error = ConversionError;
    fn try_from(data: &proto_Encrypted) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        match &data.field_type {
            proto_CipherType::CIPHER_AES128_CTR => Ok(Cipher::Aes128Ctr(Aes128CtrCipher {
                encrypted: data.secret.clone(),
                iv: data.iv.clone(),
                mac: match data.mac.as_ref() {
                    Some(mac) => MacType::try_from(mac),
                    None => Err(ConversionError::FieldIsEmpty("mac".to_string())),
                }?,
            })),
            proto_CipherType::CIPHER_UNKNOWN => {
                Err(ConversionError::FieldIsEmpty("cipher_type".to_string()))
            }
        }
    }
}

/// From Protobuf Message
impl TryFrom<&proto_Encrypted_oneof_kdf_type> for Kdf {
    type Error = ConversionError;
    fn try_from(data: &proto_Encrypted_oneof_kdf_type) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        match data {
            proto_Encrypted_oneof_kdf_type::kdf_scrypt(value) => Ok(Kdf::Scrypt(
                ScryptKdf {
                    dklen: value.dklen,
                    salt: value.salt.clone(),
                    n: value.n,
                    r: value.r,
                    p: value.p,
                }
                .verify()
                .map_err(|_| ConversionError::InvalidFieldValue("kdf_scrypt".to_string()))?,
            )),
            proto_Encrypted_oneof_kdf_type::kdf_pbkdf(value) => Ok(Kdf::Pbkdf2(Pbkdf2 {
                dklen: value.dklen,
                c: value.c,
                salt: value.salt.clone(),
                prf: PrfType::try_from(value.prf)?,
            })),
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
    type Error = ConversionError;
    fn try_from(value: &Pbkdf2) -> Result<Self, Self::Error> {
        let mut result = proto_Pbkdf2::new();
        result.set_dklen(value.dklen);
        result.set_salt(value.salt.clone());
        result.set_c(value.c);
        match value.prf {
            PrfType::HmacSha256 => {
                result.set_prf(proto_PrfType::PRF_HMAC_SHA256);
            }
            PrfType::HmacSha512 => {
                return Err(ConversionError::UnsupportedValue("prf".to_string()))
            }
        };
        Ok(result)
    }
}

/// From Protobuf Message
impl TryFrom<&proto_Encrypted> for Encrypted {
    type Error = ConversionError;
    fn try_from(data: &proto_Encrypted) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        let cipher = Cipher::try_from(data)?;
        let kdf = match &data.kdf_type {
            Some(kdf_type) => Kdf::try_from(kdf_type),
            None => Err(ConversionError::FieldIsEmpty("kdf_type".to_string())),
        }?;
        Ok(Encrypted { cipher, kdf })
    }
}

/// To Protobuf Message
impl TryFrom<&Encrypted> for proto_Encrypted {
    type Error = ConversionError;

    fn try_from(value: &Encrypted) -> Result<Self, Self::Error> {
        let mut encrypted = proto_Encrypted::new();
        encrypted.set_iv(value.get_iv().clone());
        encrypted.set_secret(value.get_message().clone());
        match &value.kdf {
            Kdf::Scrypt(x) => encrypted.set_kdf_scrypt(proto_ScryptKdf::from(x)),
            Kdf::Pbkdf2(x) => encrypted.set_kdf_pbkdf(proto_Pbkdf2::try_from(x)?),
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
