//! # Serialize keystore files (UTC / JSON) encrypted with a passphrase

mod address;
mod error;

pub use self::address::try_extract_address;
use self::error::SerializeError;
use keystore::KeyFile;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use uuid::Uuid;

/// Supported keystore file versions (only current V3 now)
pub static SUPPORTED_VERSIONS: &'static [u8] = &[3];

impl Encodable for KeyFile {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_struct("KeyFile", 3, |s| {
            (s.emit_struct_field("version", 0, |s| s.emit_usize(3)))?;
            (s.emit_struct_field("id", 1, |s| self.id.encode(s)))?;

            if let Some(addr) = self.address {
                (s.emit_struct_field("address", 2, |s| addr.encode(s)))?;
            }

            Ok(())
        })
    }
}

impl Decodable for KeyFile {
    fn decode<D: Decoder>(d: &mut D) -> Result<KeyFile, D::Error> {
        d.read_struct("KeyFile", 2, |d| {
            let ver = (d.read_struct_field("version", 0, |d| d.read_u8()))?;

            if !SUPPORTED_VERSIONS.contains(&ver) {
                return Err(d.error(&SerializeError::UnsupportedVersion(ver).to_string()));
            }

            let id =
                (d.read_struct_field("id", 1, |d| d.read_str())
                     .and_then(|s| Uuid::parse_str(&s).map_err(|e| d.error(&e.to_string()))))?;

            let addr = d.read_struct_field("address", 2, |d| Decodable::decode(d))?;

            let mut key_file = KeyFile::from(id);

            if let Some(addr) = addr {
                key_file.with_address(&addr);
            }

            Ok(key_file)
        })
    }
}

#[cfg(test)]
mod tests {
    use keystore::KeyFile;
    use rustc_serialize::json;

    #[test]
    fn should_decode_encode_keyfile_with_address() {
        let str = r#"{
          "version": 3,
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9",
          "address": "3f4e0668c20e100d7c2a27d4b177ac65b2875d26",
          "name": "",
          "meta": "{}"
        }"#;

        let exp = "{\"version\":3,\"id\":\"9bec4728-37f9-4444-9990-2ba70ee038e9\",\"address\":\
                   \"3f4e0668c20e100d7c2a27d4b177ac65b2875d26\"}";

        let key = json::decode::<KeyFile>(str).unwrap();

        assert_eq!(json::encode(&key).unwrap(), exp);
    }

    #[test]
    fn should_decode_encode_keyfile_without_address() {
        let str = r#"{
          "version": 3,
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9",
          "name": "",
          "meta": "{}"
        }"#;

        let exp = "{\"version\":3,\"id\":\"9bec4728-37f9-4444-9990-2ba70ee038e9\"}";

        let key = json::decode::<KeyFile>(str).unwrap();

        assert_eq!(json::encode(&key).unwrap(), exp);
    }

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
