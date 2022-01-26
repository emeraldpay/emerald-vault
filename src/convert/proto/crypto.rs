use crate::{
    convert::error::ConversionError,
    proto::crypto::{
        Encrypted as proto_Encrypted,
        Encrypted_CipherType as proto_CipherType,
        Encrypted_oneof_kdf_type as proto_Encrypted_oneof_kdf_type,
        GlobalKey as proto_GlobalKey,
        GlobalKeyRef as proto_GlobalKeyRef,
        Mac as proto_Mac,
        Mac_MacType as proto_MacType,
        Pbkdf2 as proto_Pbkdf2,
        PrfType as proto_PrfType,
        ScryptKdf as proto_ScryptKdf,
        Argon2 as proto_Argon2,
    },
    structs::{
        crypto::{Aes128CtrCipher, Cipher, Encrypted, Kdf, MacType, Pbkdf2, PrfType, ScryptKdf},
        types::IsVerified,
    },
};
use std::convert::{TryFrom, TryInto};
use protobuf::Message;
use crate::structs::crypto::{Argon2, GlobalKey, GlobalKeyRef};

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
            proto_Encrypted_oneof_kdf_type::kdf_argon(value) => Ok(
                Kdf::Argon2(
                    Argon2 {
                        mem: value.mem,
                        iterations: value.iterations,
                        parallel: value.parallel,
                        salt: value.salt.clone(),
                    }
                )
            ),
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

/// To Protobuf Message
impl From<&Argon2> for proto_Argon2 {
    fn from(value: &Argon2) -> Self {
        let mut result = proto_Argon2::new();
        result.set_salt(value.salt.clone());
        result.set_mem(value.mem);
        result.set_iterations(value.iterations);
        result.set_parallel(value.parallel);
        result
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
        let global_key_ref = match data.global_key.as_ref() {
            Some(r) => Some(GlobalKeyRef::try_from(r)?),
            None => None
        };
        Ok(Encrypted { cipher, kdf, global_key: global_key_ref })
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
            Kdf::Argon2(x) => encrypted.set_kdf_argon(proto_Argon2::from(x)),
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
        if let Some(g) = &value.global_key {
            encrypted.set_global_key(proto_GlobalKeyRef::try_from(g)?);
        }
        Ok(encrypted)
    }
}

impl TryFrom<proto_GlobalKey> for GlobalKey {
    type Error = ConversionError;

    fn try_from(value: proto_GlobalKey) -> Result<Self, Self::Error> {
        if value.key.is_none() {
            return Err(ConversionError::FieldIsEmpty("key".to_string()));
        }
        let proto_encrypted = value.key.unwrap();
        let encrypted: Encrypted = Encrypted::try_from(&proto_encrypted)?;
        Ok(GlobalKey {
            key: encrypted
        })
    }
}

impl TryFrom<&[u8]> for GlobalKey {
    type Error = ConversionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let proto = proto_GlobalKey::parse_from_bytes(value)?;
        GlobalKey::try_from(proto)
    }
}

impl TryFrom<&GlobalKey> for proto_GlobalKey {
    type Error = ConversionError;

    fn try_from(value: &GlobalKey) -> Result<Self, Self::Error> {
        let mut msg = proto_GlobalKey::new();
        let mut proto_key: proto_Encrypted = proto_Encrypted::try_from(&value.key)?;
        msg.set_key(proto_key);
        Ok(msg)
    }
}

impl TryFrom<&proto_GlobalKeyRef> for GlobalKeyRef {
    type Error = ConversionError;

    fn try_from(value: &proto_GlobalKeyRef) -> Result<Self, Self::Error> {
        let nonce = value.nonce.clone().try_into()
            .map_err(|_| ConversionError::InvalidLength)?;
        Ok(GlobalKeyRef {
            nonce
        })
    }
}

impl TryFrom<&GlobalKeyRef> for proto_GlobalKeyRef {
    type Error = ConversionError;

    fn try_from(value: &GlobalKeyRef) -> Result<Self, Self::Error> {
        let mut msg = proto_GlobalKeyRef::new();
        msg.set_nonce(value.nonce.to_vec());
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::{TryFrom, TryInto};
    use protobuf::Message;
    use crate::structs::crypto::{Encrypted, GlobalKey};
    use crate::proto::crypto::{GlobalKey as proto_GlobalKey};

    #[test]
    fn write_read_global_key() {
        let global = GlobalKey {
            key: Encrypted::encrypt("global-key".as_bytes().to_vec(), "test".as_bytes(), None).unwrap()
        };
        let buf: Vec<u8> = proto_GlobalKey::try_from(&global).unwrap().write_to_bytes().unwrap();
        let global_read = GlobalKey::try_from(buf.as_slice()).unwrap();
        assert_eq!(&global, &global_read);

        let global_ne = GlobalKey {
            key: Encrypted::encrypt("global-key-2".as_bytes().to_vec(), "test".as_bytes(), None).unwrap()
        };

        assert_ne!(global_ne, global_read);
    }
}
