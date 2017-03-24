use rustc_serialize::hex::{FromHex, FromHexError, ToHex};
use std::{error, fmt};
use std::str::FromStr;

/// Fixed bytes number to represent `Address`
pub const ADDRESS_BYTES: usize = 20;

/// Account address (20 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; ADDRESS_BYTES]);

#[derive(Debug, Clone)]
/// `Address` struct parse errors
pub enum AddressParseError {
    /// An invalid given length, not `ADDRESS_BYTES`.
    InvalidLength(usize),
    /// An unexpected hexadecimal prefix (should be '0x')
    UnexpectedPrefix(String),
    /// An unexpected hexadecimal encoding error
    UnexpectedEncoding(FromHexError),
}

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
    /// let addr = emerald::Address::new([0; emerald::ADDRESS_BYTES]);
    /// assert_eq!(addr.to_string(), "0x0000000000000000000000000000000000000000");
    /// ```
    pub fn new(data: [u8; ADDRESS_BYTES]) -> Self {
        Address(data)
    }

    /// Try to convert a byte vector to `Address`.
    ///
    /// # Arguments
    ///
    /// * `vec` - A byte vector with `ADDRESS_BYTES` length
    ///
    /// # Example
    ///
    /// ```
    /// let addr = emerald::Address::try_from(vec![0; emerald::ADDRESS_BYTES]).unwrap();
    /// assert_eq!(addr.to_string(), "0x0000000000000000000000000000000000000000");
    /// ```
    pub fn try_from(vec: Vec<u8>) -> Result<Self, AddressParseError> {
        if vec.len() != ADDRESS_BYTES {
            return Err(AddressParseError::InvalidLength(vec.len()));
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

        s.from_hex().map_err(AddressParseError::from).and_then(Address::try_from)
    }
}

impl From<FromHexError> for AddressParseError {
    fn from(err: FromHexError) -> Self {
        AddressParseError::UnexpectedEncoding(err)
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
            AddressParseError::InvalidLength(len) => {
                write!(f, "Address invalid given length: {}", len)
            }
            AddressParseError::UnexpectedPrefix(ref str) => {
                write!(f, "Unexpected address hexadecimal prefix: {}", str)
            }
            AddressParseError::UnexpectedEncoding(ref err) => {
                write!(f, "Unexpected address hexadecimal encoding: {}", err)
            }
        }
    }
}

impl error::Error for AddressParseError {
    fn description(&self) -> &str {
        "Address parsing error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            AddressParseError::UnexpectedEncoding(ref err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ADDRESS_BYTES, Address};

    #[test]
    fn should_display_empty_address() {
        assert_eq!(Address::new([0; ADDRESS_BYTES]).to_string(),
                   "0x0000000000000000000000000000000000000000");
    }

    #[test]
    fn should_display_real_address() {
        assert_eq!(Address::new([0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65,
                                 0x04, 0x73, 0x80, 0x89, 0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4])
                       .to_string(),
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
}
