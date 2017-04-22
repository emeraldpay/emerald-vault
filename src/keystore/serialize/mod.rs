//! # Serialize keystore files (UTC / JSON) encrypted with a passphrase

mod address;
#[macro_use]
mod byte_array;
mod crypto;
mod error;
mod meta;

pub use self::address::try_extract_address;
use self::crypto::Crypto;
use self::error::SerializeError;
use address::Address;
use keystore::KeyFile;
use keystore::meta::MetaInfo;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use uuid::Uuid;

/// Keystore file current version used for serializing
pub const CURRENT_VERSION: u8 = 3;

/// Supported keystore file versions (only current V3 now)
pub const SUPPORTED_VERSIONS: &'static [u8] = &[CURRENT_VERSION];

impl Decodable for KeyFile {
    fn decode<D: Decoder>(d: &mut D) -> Result<KeyFile, D::Error> {
        let ser = (SerializableKeyFile::decode(d))?;

        if !SUPPORTED_VERSIONS.contains(&ser.version) {
            return Err(d.error(&SerializeError::UnsupportedVersion(ser.version).to_string()));
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
    name: Option<String>,
    meta: Option<MetaInfo>,
}

impl From<KeyFile> for SerializableKeyFile {
    fn from(key_file: KeyFile) -> Self {
        SerializableKeyFile {
            version: CURRENT_VERSION,
            id: key_file.uuid,
            address: key_file.address,
            crypto: Crypto::from(key_file.clone()),
            name: key_file.name,
            meta: key_file.meta,
        }
    }
}

impl From<SerializableKeyFile> for KeyFile {
    fn from(ser: SerializableKeyFile) -> KeyFile {
        let mut kf = KeyFile {
            uuid: ser.id,
            address: ser.address,
            name: ser.name,
            meta: None,
            ..KeyFile::from(ser.crypto)
        };

        match ser.meta {
            Some(m) => kf.with_meta(m),
            _ => {}
        }

        kf
    }
}

#[cfg(test)]
mod tests {
    use keystore::KeyFile;
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
