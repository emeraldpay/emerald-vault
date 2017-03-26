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

/// A keystore file corresponds UTC / JSON format (Web3 Secret Storage)
#[derive(Debug, Clone, PartialEq, Eq, RustcDecodable, RustcEncodable)]
pub struct KeyFile {
    pub address: Address,
}

/// Keystore file parser errors
#[derive(Debug)]
pub enum KeyFileParserError {
    /// An unexpected UTC / JSON encoding error
    UnexpectedEncoding(json::DecoderError),
}

impl KeyFile {
    #[allow(dead_code)]
    fn new(addr: &Address) -> Self {
        KeyFile { address: *addr }
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
        write!(f, "Keystore file: {}", self.address)
    }
}

impl fmt::Display for KeyFileParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyFileParserError::UnexpectedEncoding(ref err) => {
                write!(f, "Unexpected UTC / JSON encoding: {}", err)
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
    use address::Address;
    use rustc_serialize::json;

    const EXAMPLE_JSON: &'static str = r#"{
      "address": "3f4e0668c20e100d7c2a27d4b177ac65b2875d26",
      "name": "",
      "meta": "{}"
    }"#;

    #[test]
    fn should_encode_keyfile() {
        let key_file =
            KeyFile::new(&"0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b".parse::<Address>().unwrap());

        assert_eq!(json::encode(&key_file).unwrap(),
                   r#"{"address":"008aeeda4d805471df9b2a5b0f38a0c3bcba786b"}"#);
    }

    #[test]
    fn should_decode_keyfile() {
        assert_eq!(EXAMPLE_JSON.parse::<KeyFile>().unwrap(),
                   KeyFile::new(&"0x3f4e0668c20e100d7c2a27d4b177ac65b2875d26"
                                     .parse::<Address>()
                                     .unwrap()));
    }
}
