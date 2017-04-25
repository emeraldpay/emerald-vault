//! # Serialize keystore files (UTC / JSON) encrypted with a passphrase module

mod address;
#[macro_use]
mod byte_array;
mod crypto;
mod error;

pub use self::address::try_extract_address;
use self::crypto::Crypto;
use self::error::Error;
use super::Address;
use super::KeyFile;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use uuid::Uuid;

/// Keystore file current version used for serializing
pub const CURRENT_VERSION: u8 = 3;

/// Supported keystore file versions (only current V3 now)
pub const SUPPORTED_VERSIONS: &'static [u8] = &[CURRENT_VERSION];

impl Decodable for KeyFile {
    fn decode<D: Decoder>(d: &mut D) -> Result<KeyFile, D::Error> {
        let ser = SerializableKeyFile::decode(d)?;

        if !SUPPORTED_VERSIONS.contains(&ser.version) {
            return Err(d.error(&Error::UnsupportedVersion(ser.version).to_string()));
        }

        Ok(KeyFile::from(ser))
    }
}

impl Encodable for KeyFile {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        SerializableKeyFile::from(self.clone()).encode(s)
    }
}

/// A serializable keystore file (UTC / JSON format)
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
struct SerializableKeyFile {
    version: u8,
    id: Uuid,
    address: Option<Address>,
    crypto: Crypto,
}

impl From<KeyFile> for SerializableKeyFile {
    fn from(key_file: KeyFile) -> Self {
        SerializableKeyFile {
            version: CURRENT_VERSION,
            id: key_file.uuid,
            address: key_file.address,
            crypto: Crypto::from(key_file),
        }
    }
}

impl From<SerializableKeyFile> for KeyFile {
    fn from(ser: SerializableKeyFile) -> KeyFile {
        KeyFile {
            uuid: ser.id,
            address: ser.address,
            ..KeyFile::from(ser.crypto)
        }
    }
}

#[cfg(test)]
mod tests {
    pub use super::*;
    use rustc_serialize::json;

    #[test]
    fn should_catch_unsupported_keyfile_version() {
        let str = r#"{
          "version": 2,
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(json::decode::<KeyFile>(str).is_err());
    }

    #[test]
    fn should_catch_keyfile_version_malformed() {
        let str = r#"{
          "version": "x",
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(json::decode::<KeyFile>(str).is_err());
    }

    #[test]
    fn should_catch_keyfile_uuid_malformed() {
        let str = r#"{
          "version": 3,
          "id": "__ec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(json::decode::<KeyFile>(str).is_err());
    }

    #[test]
    fn should_catch_absent_keyfile_uuid() {
        let str = r#"{"version": 3}"#;

        assert!(json::decode::<KeyFile>(str).is_err());
    }
}
