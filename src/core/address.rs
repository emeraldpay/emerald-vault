//! # Account address (20 bytes)

use super::util::to_arr;
use super::Error;
use hex;
use std::str::FromStr;
use std::{fmt, ops};

/// Fixed bytes number to represent `Address`
pub const ADDRESS_BYTES: usize = 20;

/// Account address (20 bytes)
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub [u8; ADDRESS_BYTES]);

impl Address {
    /// Try to convert a byte vector to `Address`.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice with `ADDRESS_BYTES` length
    ///
    /// # Example
    ///
    /// ```
    /// let addr = emerald_rs::Address::try_from(&[0u8; emerald_rs::ADDRESS_BYTES]).unwrap();
    /// assert_eq!(addr.to_string(), "0x0000000000000000000000000000000000000000");
    /// ```
    pub fn try_from(data: &[u8]) -> Result<Self, Error> {
        if data.len() != ADDRESS_BYTES {
            return Err(Error::InvalidLength(data.len()));
        }

        Ok(Address(to_arr(data)))
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
        Address(bytes)
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != ADDRESS_BYTES * 2 && !s.starts_with("0x") {
            return Err(Error::InvalidHexLength(s.to_string()));
        }

        let value = if s.starts_with("0x") {
            s.split_at(2).1
        } else {
            s
        };

        Address::try_from(hex::decode(&value)?.as_slice())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_display_zero_address() {
        assert_eq!(
            Address::default().to_string(),
            "0x0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn should_display_real_address() {
        let addr = Address([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            addr.to_string(),
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
        );
    }

    #[test]
    fn should_parse_real_address() {
        let addr = Address([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse::<Address>()
                .unwrap(),
            addr
        );
    }

    #[test]
    fn should_parse_real_address_without_prefix() {
        let addr = Address([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            "0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse::<Address>()
                .unwrap(),
            addr
        );
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
