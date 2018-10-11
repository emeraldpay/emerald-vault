//! # Serialize keystore files (UTC / JSON) encrypted with a passphrase module

mod address;
#[macro_use]
pub mod byte_array;
mod crypto;
mod error;

pub use self::address::try_extract_address;
pub use self::crypto::{CoreCrypto, Iv, Mac};
pub use self::error::Error;
use super::core::{self, Address};
use super::util;
use super::HdwalletCrypto;
use super::{Cipher, CryptoType, KdfParams, KeyFile, Salt, CIPHER_IV_BYTES};
use serde::ser;
use serde::{Serialize, Serializer};
use serde_json;
use uuid::Uuid;

/// Keystore file current version used for serializing
pub const CURRENT_VERSION: u8 = 3;

/// Supported keystore file versions (only current V3 now)
pub const SUPPORTED_VERSIONS: &[u8] = &[CURRENT_VERSION];

/// A serializable keystore file (UTC / JSON format)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializableKeyFileCore {
    version: u8,
    id: Uuid,
    address: Address,
    name: Option<String>,
    description: Option<String>,
    visible: Option<bool>,
    crypto: CoreCrypto,
}

impl SerializableKeyFileCore {
    fn try_from(kf: KeyFile) -> Result<Self, Error> {
        let cr = CoreCrypto::try_from(&kf)?;

        Ok(SerializableKeyFileCore {
            version: CURRENT_VERSION,
            id: kf.uuid,
            address: kf.address,
            name: kf.name.clone(),
            description: kf.description.clone(),
            visible: kf.visible,
            crypto: cr,
        })
    }
}

impl Into<KeyFile> for SerializableKeyFileCore {
    fn into(self) -> KeyFile {
        KeyFile {
            name: self.name,
            description: self.description,
            address: self.address,
            visible: self.visible,
            uuid: self.id,
            crypto: CryptoType::Core(self.crypto),
        }
    }
}

/// A serializable keystore file (UTC / JSON format)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializableKeyFileHD {
    version: u8,
    id: Uuid,
    address: Address,
    name: Option<String>,
    description: Option<String>,
    visible: Option<bool>,
    crypto: HdwalletCrypto,
}

impl SerializableKeyFileHD {
    fn try_from(kf: &KeyFile) -> Result<Self, Error> {
        let cr = HdwalletCrypto::try_from(kf)?;

        Ok(SerializableKeyFileHD {
            version: CURRENT_VERSION,
            id: kf.uuid,
            address: kf.address,
            name: kf.name.clone(),
            description: kf.description.clone(),
            visible: kf.visible,
            crypto: cr,
        })
    }
}

impl Into<KeyFile> for SerializableKeyFileHD {
    fn into(self) -> KeyFile {
        KeyFile {
            name: self.name,
            description: self.description,
            address: self.address,
            visible: self.visible,
            uuid: self.id,
            crypto: CryptoType::HdWallet(self.crypto),
        }
    }
}

impl KeyFile {
    /// Decode `Keyfile` from JSON
    /// Handles different variants of `crypto` section
    ///
    pub fn decode(f: &str) -> Result<KeyFile, Error> {
        let buf = f.to_string().to_lowercase();
        let mut ver = 0;

        let kf = serde_json::from_str::<SerializableKeyFileCore>(&buf)
            .and_then(|core| {
                ver = core.version;
                Ok(core.into())
            }).or_else(|_| {
                serde_json::from_str::<SerializableKeyFileHD>(&buf).and_then(|hd| {
                    ver = hd.version;
                    Ok(hd.into())
                })
            }).map_err(Error::from)?;

        if !SUPPORTED_VERSIONS.contains(&ver) {
            return Err(Error::UnsupportedVersion(ver));
        }

        Ok(kf)
    }
}

impl Serialize for KeyFile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match SerializableKeyFileCore::try_from(self.clone()) {
            Ok(sf) => sf.serialize(serializer),
            Err(_) => match SerializableKeyFileHD::try_from(self) {
                Ok(s) => s.serialize(serializer),
                Err(e) => Err(ser::Error::custom(e)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage::generate_filename;
    use tests::*;

    #[test]
    fn should_catch_unsupported_keyfile_version() {
        let s = r#"{
          "version": 2,
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(KeyFile::decode(s).is_err());
    }

    #[test]
    fn should_catch_keyfile_version_malformed() {
        let s = r#"{
          "version": "x",
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(KeyFile::decode(s).is_err());
    }

    #[test]
    fn should_catch_keyfile_uuid_malformed() {
        let s = r#"{
          "version": 3,
          "id": "__ec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(KeyFile::decode(s).is_err());
    }

    #[test]
    fn should_catch_absent_keyfile_uuid() {
        let s = r#"{"version": 3}"#;

        assert!(KeyFile::decode(s).is_err());
    }

    #[test]
    fn should_generate_filename() {
        let re = Regex::new(r"^UTC--\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z--*").unwrap();

        assert!(re.is_match(&generate_filename("9bec4728-37f9-4444-9990-2ba70ee038e9"),));
    }
}
