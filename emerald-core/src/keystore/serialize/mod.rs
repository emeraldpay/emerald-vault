//! # Serialize keystore files (UTC / JSON) encrypted with a passphrase module

mod address;
#[macro_use]
mod byte_array;
mod crypto;
mod error;

pub use self::address::try_extract_address;
pub use self::crypto::{CoreCrypto, Iv, Mac, Salt, decode_str};
pub use self::error::Error;
use super::{CIPHER_IV_BYTES, Cipher, CryptoType, KDF_SALT_BYTES, Kdf, KeyFile};
use super::HdwalletCrypto;
use super::core::{self, Address};
use super::util;
use rustc_serialize::{Encodable, Encoder, json};
use uuid::Uuid;

/// Keystore file current version used for serializing
pub const CURRENT_VERSION: u8 = 3;

/// Supported keystore file versions (only current V3 now)
pub const SUPPORTED_VERSIONS: &'static [u8] = &[CURRENT_VERSION];

/// A serializable keystore file (UTC / JSON format)
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
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
        let cr = CoreCrypto::try_from(kf.clone())?;

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
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
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
    fn try_from(kf: KeyFile) -> Result<Self, Error> {
        let cr = HdwalletCrypto::try_from(kf.clone())?;

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
    pub fn decode(f: String) -> Result<KeyFile, Error> {
        let buf1 = f.clone();
        let buf2 = f.clone();
        let mut ver = 0;

        let kf = json::decode::<SerializableKeyFileCore>(&buf1)
            .and_then(|core| {
                ver = core.version;
                Ok(core.into())
            })
            .or_else(|_| {
                json::decode::<SerializableKeyFileHD>(&buf2).and_then(|hd| {
                    ver = hd.version;
                    Ok(hd.into())
                })
            })
            .map_err(|e| Error::from(e))?;

        if !SUPPORTED_VERSIONS.contains(&ver) {
            return Err(Error::UnsupportedVersion(ver));
        }

        Ok(kf)
    }
}

impl Encodable for KeyFile {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        match SerializableKeyFileCore::try_from(self.clone()) {
            Ok(sf) => sf.encode(s),
            Err(_) => {
                match SerializableKeyFileHD::try_from(self.clone()) {
                    Ok(sf) => sf.encode(s),
                    Err(_) => Ok(()),
                }
            }

        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_catch_unsupported_keyfile_version() {
        let str = r#"{
          "version": 2,
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(KeyFile::decode(str.to_string()).is_err());
    }

    #[test]
    fn should_catch_keyfile_version_malformed() {
        let str = r#"{
          "version": "x",
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(KeyFile::decode(str.to_string()).is_err());
    }

    #[test]
    fn should_catch_keyfile_uuid_malformed() {
        let str = r#"{
          "version": 3,
          "id": "__ec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(KeyFile::decode(str.to_string()).is_err());
    }

    #[test]
    fn should_catch_absent_keyfile_uuid() {
        let str = r#"{"version": 3}"#;

        assert!(KeyFile::decode(str.to_string()).is_err());
    }

    #[test]
    fn should_generate_filename() {
        let re = Regex::new(r"^UTC--\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z--*").unwrap();

        assert!(re.is_match(
            &generate_filename("9bec4728-37f9-4444-9990-2ba70ee038e9"),
        ));
    }
}
