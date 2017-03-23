use regex::Regex;
use rustc_serialize::hex::{FromHex, FromHexError, ToHex};
use std::{error, fmt};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

const ADDRESS_BYTES: usize = 20;

/// Account address (20 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; ADDRESS_BYTES]);

#[derive(Debug, Clone)]
/// `Address` struct parse errors
pub enum AddressParseError {
    /// An invalid given length, not `ADDRESS_BYTES`.
    InvalidGivenLength(usize),
    /// An unexpected hexadecimal prefix (should be '0x')
    UnexpectedPrefix(String),
    /// An unexpected hexadecimal encoding error
    UnexpectedEncoding(FromHexError),
}

impl Address {
    /// Create a new Address from 20 bytes
    pub fn new(data: [u8; ADDRESS_BYTES]) -> Self {
        Address(data)
    }

    fn try_from(vec: Vec<u8>) -> Result<Self, AddressParseError> {
        if vec.len() != ADDRESS_BYTES {
            return Err(AddressParseError::InvalidGivenLength(vec.len()));
        }

        let mut addr = [0; ADDRESS_BYTES];

        addr.clone_from_slice(vec.as_slice());

        Ok(Address(addr))
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err(AddressParseError::UnexpectedPrefix(s.to_owned()));
        }

        let (_, s) = s.split_at(2);

        s.from_hex().map_err(AddressParseError::UnexpectedEncoding).and_then(Address::try_from)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", self.0.to_hex())
    }
}

impl fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AddressParseError::InvalidGivenLength(len) => {
                write!(f, "Address invalid given length: {}", len)
            }
            AddressParseError::UnexpectedPrefix(ref str) => {
                write!(f, "Unexpected address hexadecimal prefix: {}", str)
            }
            AddressParseError::UnexpectedEncoding(err) => {
                write!(f, "Unexpected address hexadecimal encoding: {}", err)
            }
        }
    }
}

impl error::Error for AddressParseError {
    fn description(&self) -> &str {
        "Address parsing error"
    }
}

/// if we have specified address in out keystore return `true`, `false` otherwise
pub fn address_exists<P: AsRef<Path>>(path: P, addr: &str) -> bool {
    let addr = &addr.to_owned()[2..]; /* cut '0x' prefix */

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

        match extract_address(&text) {
            Some(a) if a == addr => return true,
            _ => continue,
        }
    }

    false
}

fn extract_address(text: &str) -> Option<&str> {
    lazy_static! {
        static ref ADDR_RE: Regex = Regex::new(r#"address.+([a-fA-F0-9]{40})"#).unwrap();
    }

    ADDR_RE.captures(text).and_then(|gr| gr.get(1)).map(|m| m.as_str())
}

#[cfg(test)]
mod tests {
    use super::{Address, extract_address};

    #[test]
    fn should_display_empty_address() {
        assert_eq!(format!("{}", Address::new([0; 20])),
                   "0x0000000000000000000000000000000000000000");
    }

    #[test]
    fn should_display_real_address() {
        assert_eq!(format!("{}",
                           Address::new([0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97,
                                         0x65, 0x04, 0x73, 0x80, 0x89, 0x89, 0x19, 0xc5, 0xcb,
                                         0x56, 0xf4])),
                   "0x0e7c045110b8dbf29765047380898919c5cb56f4");
    }

    #[test]
    fn should_parse_real_address() {
        assert_eq!("0x0e7c045110b8dbf29765047380898919c5cb56f4".parse::<Address>().unwrap(),
                   Address::new([0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65,
                                 0x04, 0x73, 0x80, 0x89, 0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4]));
    }

    #[test]
    fn should_catch_wrong_address_encoding() {
        assert!("0x___c045110b8dbf29765047380898919c5cb56f4".parse::<Address>().is_err());
    }

    #[test]
    fn should_catch_wrong_address_insufficient_length() {
        assert!("0x0e7c045110b8dbf297650473808989".parse::<Address>().is_err());
    }

    #[test]
    fn should_catch_wrong_address_excess_length() {
        assert!("0x0e7c045110b8dbf29765047380898919c5cb56f400000000".parse::<Address>().is_err());
    }

    #[test]
    fn should_catch_wrong_address_prefix() {
        assert!("0_0e7c045110b8dbf29765047380898919c5cb56f4".parse::<Address>().is_err());
    }

    #[test]
    fn should_catch_missing_address_prefix() {
        assert!("_".parse::<Address>().is_err());
    }

    #[test]
    fn should_catch_empty_address_string() {
        assert!("".parse::<Address>().is_err());
    }

    #[test]
    fn should_extract_address() {
        assert_eq!(extract_address(r#"address: '008aeeda4d805471df9b2a5b0f38a0c3bcba786b',"#),
                   Some("008aeeda4d805471df9b2a5b0f38a0c3bcba786b"));
        assert_eq!(extract_address(r#"  "address": "0047201aed0b69875b24b614dda0270bcd9f11cc","#),
                   Some("0047201aed0b69875b24b614dda0270bcd9f11cc"));
        assert_eq!(extract_address(r#"  },
                                      "address": "3f4e0668c20e100d7c2a27d4b177ac65b2875d26",
                                      "name": "",
                                      "meta": "{}"
                                    }"#),
                   Some("3f4e0668c20e100d7c2a27d4b177ac65b2875d26"));
    }

    #[test]
    fn should_ignore_empty() {
        assert_eq!(extract_address(""), None);
    }

    #[test]
    fn should_ignore_pointless() {
        assert_eq!(extract_address(r#""version": 3"#), None);
    }
}
