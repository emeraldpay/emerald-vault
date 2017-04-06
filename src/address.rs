//! # Account address (20 bytes)

use rustc_serialize::hex::{self, FromHex, ToHex};
use std::{error, fmt, ops};
use std::str::FromStr;

/// Fixed bytes number to represent `Address`
pub const ADDRESS_BYTES: usize = 20;

/// Account address (20 bytes)
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address([u8; ADDRESS_BYTES]);

impl Address {
    /// Create a new `Address` from given 20 bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - An fixed byte array with `ADDRESS_BYTES` length
    ///
    /// # Example
    ///
    /// ```
    /// assert_eq!(emerald::Address::default().to_string(),
    ///            "0x0000000000000000000000000000000000000000");
    /// ```
    pub fn new(data: [u8; ADDRESS_BYTES]) -> Self {
        Address(data)
    }

    /// Try to convert a byte vector to `Address`.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice with `ADDRESS_BYTES` length
    ///
    /// # Example
    ///
    /// ```
    /// let addr = emerald::Address::try_from(&vec![0; emerald::ADDRESS_BYTES]).unwrap();
    /// assert_eq!(addr.to_string(), "0x0000000000000000000000000000000000000000");
    /// ```
    pub fn try_from(data: &[u8]) -> Result<Self, AddressParserError> {
        if data.len() != ADDRESS_BYTES {
            return Err(AddressParserError::InvalidLength(data.len()));
        }

        let mut bytes = [0; ADDRESS_BYTES];

        bytes.clone_from_slice(data);

        Ok(Address(bytes))
    }
}

impl ops::Deref for Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; ADDRESS_BYTES]> for Address {
    fn from(bytes: [u8; ADDRESS_BYTES]) -> Self {
        Address::new(bytes)
    }
}

impl FromStr for Address {
    type Err = AddressParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err(AddressParserError::UnexpectedPrefix(s.to_string()));
        }

        let (_, s) = s.split_at(2);

        s.from_hex()
            .map_err(AddressParserError::UnexpectedEncoding)
            .and_then(|v| Address::try_from(&v))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", self.0.to_hex())
    }
}

/// `Address` struct parser errors
#[derive(Debug)]
pub enum AddressParserError {
    /// An invalid given length, not `ADDRESS_BYTES`.
    InvalidLength(usize),
    /// An unexpected hexadecimal prefix (should be '0x')
    UnexpectedPrefix(String),
    /// An unexpected hexadecimal encoding error
    UnexpectedEncoding(hex::FromHexError),
}

impl fmt::Display for AddressParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AddressParserError::InvalidLength(len) => {
                write!(f, "Address invalid given length: {}", len)
            }
            AddressParserError::UnexpectedPrefix(ref str) => {
                write!(f, "Unexpected address hexadecimal prefix: {}", str)
            }
            AddressParserError::UnexpectedEncoding(ref err) => {
                write!(f, "Unexpected address hexadecimal encoding: {}", err)
            }
        }
    }
}

impl error::Error for AddressParserError {
    fn description(&self) -> &str {
        "Address parser error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            AddressParserError::UnexpectedEncoding(ref err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Address;

    #[test]
    fn should_display_zero_address() {
        assert_eq!(Address::default().to_string(),
                   "0x0000000000000000000000000000000000000000");
    }

    #[test]
    fn should_display_real_address() {
        let addr = Address::new([0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65,
                                 0x04, 0x73, 0x80, 0x89, 0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4]);

        assert_eq!(addr.to_string(),
                   "0x0e7c045110b8dbf29765047380898919c5cb56f4");
    }

    #[test]
    fn should_parse_real_address() {
        let addr = Address::new([0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65,
                                 0x04, 0x73, 0x80, 0x89, 0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4]);

        assert_eq!("0x0e7c045110b8dbf29765047380898919c5cb56f4"
                       .parse::<Address>()
                       .unwrap(),
                   addr);
    }

    #[test]
    fn should_catch_wrong_address_encoding() {
        assert!("0x___c045110b8dbf29765047380898919c5cb56f4"
                    .parse::<Address>()
                    .is_err());
    }

    #[test]
    fn should_catch_wrong_address_insufficient_length() {
        assert!("0x0e7c045110b8dbf297650473808989"
                    .parse::<Address>()
                    .is_err());
    }

    #[test]
    fn should_catch_wrong_address_excess_length() {
        assert!("0x0e7c045110b8dbf29765047380898919c5cb56f400000000"
                    .parse::<Address>()
                    .is_err());
    }

    #[test]
    fn should_catch_wrong_address_prefix() {
        assert!("0_0e7c045110b8dbf29765047380898919c5cb56f4"
                    .parse::<Address>()
                    .is_err());
    }

    #[test]
    fn should_catch_missing_address_prefix() {
        assert!("_".parse::<Address>().is_err());
    }

    #[test]
    fn should_catch_empty_address_string() {
        assert!("".parse::<Address>().is_err());
    }
}
