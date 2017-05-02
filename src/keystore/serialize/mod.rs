//! # Serialize keystore files (UTC / JSON) encrypted with a passphrase module

mod address;
#[macro_use]
mod byte_array;
mod crypto;
mod error;

use self::address::try_extract_address;
use self::crypto::Crypto;
use self::error::Error;
use super::{CIPHER_IV_BYTES, Cipher, KDF_SALT_BYTES, Kdf, KeyFile};
use super::core::{self, Address};
use super::util;
use chrono::prelude::UTC;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder, json};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use uuid::Uuid;

/// Keystore file current version used for serializing
pub const CURRENT_VERSION: u8 = 3;

/// Supported keystore file versions (only current V3 now)
pub const SUPPORTED_VERSIONS: &'static [u8] = &[CURRENT_VERSION];

impl KeyFile {
    /// Serializes into JSON file with the name format `UTC--<timestamp>Z--<uuid>`
    ///
    /// # Arguments
    ///
    /// * `dir` - path to destination directory
    /// * `addr` - a public address (optional)
    ///
    pub fn flush<P: AsRef<Path>>(&self, dir: P, addr: Option<Address>) -> Result<(), Error> {
        let path = dir.as_ref()
            .with_file_name(&generate_filename(&self.uuid.to_string()));
        let mut sf = SerializableKeyFile::from(self.clone());
        sf.address = addr;
        let json = json::encode(&sf)?;
        let mut file = File::create(&path)?;
        file.write_all(json.as_ref()).ok();
        Ok(())
    }

    /// Search of `KeyFile` by specified `Address`
    ///
    /// # Arguments
    ///
    /// * `path` - path with keystore files
    ///
    pub fn search_by_address<P: AsRef<Path>>(addr: &Address, path: P) -> Result<KeyFile, Error> {
        let entries = fs::read_dir(path)?;

        for entry in entries {
            let path = entry?.path();

            if path.is_dir() {
                continue;
            }

            let mut file = fs::File::open(path)?;
            let mut content = String::new();

            if file.read_to_string(&mut content).is_err() {
                continue;
            }
            match try_extract_address(&content) {
                Some(a) if a == *addr => {
                    return Ok(json::decode::<KeyFile>(&content)?);
                }
                _ => continue,
            }
        }

        Err(Error::NotFound)
    }
}

impl Decodable for KeyFile {
    fn decode<D: Decoder>(d: &mut D) -> Result<KeyFile, D::Error> {
        let sf = SerializableKeyFile::decode(d)?;

        if !SUPPORTED_VERSIONS.contains(&sf.version) {
            return Err(d.error(&Error::UnsupportedVersion(sf.version).to_string()));
        }

        Ok(sf.into())
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
            address: None,
            crypto: Crypto::from(key_file),
        }
    }
}

impl Into<KeyFile> for SerializableKeyFile {
    fn into(self) -> KeyFile {
        KeyFile {
            uuid: self.id,
            ..self.crypto.into()
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
fn generate_filename(uuid: &str) -> String {
    format!("UTC--{}Z--{}", &timestamp(), &uuid)
}

/// Time stamp for core file in format `yyy-mm-ddThh-mm-ss`
fn timestamp() -> String {
    // `2017-05-01T20:21:10.163281100+00:00` -> `2017-05-01T20-21-10`
    str::replace(&UTC::now().to_rfc3339(), ":", "-")
        .split('.')
        .next()
        .unwrap()
        .to_string()
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

        assert!(re.is_match(&generate_filename("9bec4728-37f9-4444-9990-2ba70ee038e9")));
    }

    #[test]
    fn should_generate_timestamp() {
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}[T]\d{2}-\d{2}-\d{2}").unwrap();

        assert!(re.is_match(&timestamp()));
    }
}
