//! Keystore files (UTC / JSON) encrypted with a passphrase

mod address;

use self::address::try_extract_address;
use address::Address;
use rustc_serialize::json;
use std::{error, fmt};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

/// A keystore file corresponds UTC / JSON format (Web3 Secret Storage)
#[derive(Debug, Clone, Eq, RustcDecodable, RustcEncodable)]
pub struct KeyFile {
    pub version: u32,
    pub id: Uuid,
    pub address: Option<Address>,
}

/// Keystore file parser errors
#[derive(Debug)]
pub enum KeyFileParserError {
    /// An unexpected UTC / JSON encoding error
    UnexpectedEncoding(json::DecoderError),
}

impl KeyFile {
    fn new() -> Self {
        KeyFile {
            version: 3,
            id: Uuid::new_v4(),
            address: None,
        }
    }
}

impl From<Uuid> for KeyFile {
    fn from(id: Uuid) -> Self {
        KeyFile {
            version: 3,
            id: id,
            address: None,
        }
    }
}

impl PartialEq for KeyFile {
    fn eq(&self, other: &KeyFile) -> bool {
        self.id == other.id
    }
}

impl FromStr for KeyFile {
    type Err = KeyFileParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        json::decode(s).map_err(KeyFileParserError::from)
    }
}

impl From<json::DecoderError> for KeyFileParserError {
    fn from(err: json::DecoderError) -> Self {
        KeyFileParserError::UnexpectedEncoding(err)
    }
}

impl fmt::Display for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keystore file: {}", self.id)
    }
}

impl fmt::Display for KeyFileParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyFileParserError::UnexpectedEncoding(ref err) => {
                write!(f, "Unexpected JSON encoding: {}", err)
            }
        }
    }
}

impl error::Error for KeyFileParserError {
    fn description(&self) -> &str {
        "Keystore file parser error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            KeyFileParserError::UnexpectedEncoding(ref err) => Some(err),
        }
    }
}

/// If we have specified address in out keystore return `true`, `false` otherwise
pub fn address_exists<P: AsRef<Path>>(path: P, addr: &Address) -> bool {
    let entries = fs::read_dir(path).expect("Expect to read a keystore directory content");

    for entry in entries {
        let path = entry.expect("Expect keystore directory entry").path();

        if path.is_dir() {
            continue;
        }

        let mut file = File::open(path).expect("Expect to open a keystore file");
        let mut text = String::new();

        if file.read_to_string(&mut text).is_err() {
            continue;
        }

        match try_extract_address(&text) {
            Some(a) if a == *addr => return true,
            _ => continue,
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::KeyFile;
    use rustc_serialize::json;

    #[test]
    fn should_decode_encode_keyfile() {
        let in_json = r#"{
          "version": 3,
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9",
          "address": "3f4e0668c20e100d7c2a27d4b177ac65b2875d26",
          "name": "",
          "meta": "{}"
        }"#;

        let out_json = "{\"version\":3,\"id\":\"9bec4728-37f9-4444-9990-2ba70ee038e9\",\
                        \"address\":\"3f4e0668c20e100d7c2a27d4b177ac65b2875d26\"}";

        assert_eq!(json::encode(&in_json.parse::<KeyFile>().unwrap()).unwrap(),
                   out_json);
    }
}
