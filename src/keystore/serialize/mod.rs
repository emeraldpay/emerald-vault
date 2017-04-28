//! # Serialize keystore files (UTC / JSON) encrypted with a passphrase module

mod address;
#[macro_use]
mod byte_array;
mod crypto;
mod error;

use self::crypto::Crypto;
use self::error::Error;
use super::{CIPHER_IV_BYTES, Cipher, KDF_SALT_BYTES, Kdf, KeyFile};
use super::core::{self, Address};
use super::util;
use chrono::prelude::UTC;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder, json};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

/// Keystore file current version used for serializing
pub const CURRENT_VERSION: u8 = 3;

/// Supported keystore file versions (only current V3 now)
pub const SUPPORTED_VERSIONS: &'static [u8] = &[CURRENT_VERSION];

impl KeyFile {
    /// Serializes into JSON file with name `UTC-<timestamp>Z--<uuid>`
    ///
    /// # Arguments
    ///
    /// * `dir` - path to destination directory
    ///
    pub fn flush<P: AsRef<Path>>(&self, dir: P) -> Result<(), Error> {
        let path = dir.as_ref()
            .with_file_name(&get_filename(&self.uuid.to_string()));
        let mut file = File::create(&path)?;
        let data = json::encode(self)?;
        file.write_all(data.as_ref()).ok();
        Ok(())
    }
}

impl Decodable for KeyFile {
    fn decode<D: Decoder>(d: &mut D) -> Result<KeyFile, D::Error> {
        let ser = SerializableKeyFile::decode(d)?;

        if !SUPPORTED_VERSIONS.contains(&ser.version) {
            return Err(d.error(&Error::UnsupportedVersion(ser.version).to_string()));
        }

        Ok(ser.into())
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

impl Into<KeyFile> for SerializableKeyFile {
    fn into(self) -> KeyFile {
        KeyFile {
            uuid: self.id,
            address: self.address,
            ..KeyFile::from(self.crypto)
        }
    }
}

/// Creates filename for keystore file in format:
/// `UTC--yyy-mm-ddThh-mm-ssZ--uuid`
///
/// # Arguments
///
/// * `uuid` - UUID for keyfile
///
fn get_filename(uuid: &str) -> String {
    format!("UTC--{}Z--{}", &get_timestamp(), &uuid)
}

/// Time stamp for core file in format `yyy-mm-ddThh-mm-ssZ`
fn get_timestamp() -> String {
    let val = UTC::now().to_rfc3339();
    let stamp = str::replace(val.as_str(), ":", "-");
    let data: Vec<&str> = stamp.split('.').collect(); //cut off milliseconds
    data[0].to_string()
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

    #[test]
    fn should_generate_filename() {
        let re = Regex::new(r"^UTC--\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z--*").unwrap();

        assert!(re.is_match(&get_filename("9bec4728-37f9-4444-9990-2ba70ee038e9")));
    }

    #[test]
    fn should_generate_timestamp() {
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}[T]\d{2}-\d{2}-\d{2}").unwrap();

        assert!(re.is_match(&get_timestamp()));
    }
}
