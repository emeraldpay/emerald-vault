/*
Copyright 2019 ETCDEV GmbH
Copyright 2020 EmeraldPay, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//! # Account address (20 bytes)

use crate::util::to_arr;
use hex;
use std::{fmt, ops, str::FromStr};
use crate::{EthereumPrivateKey, keccak256};
use bitcoin::util::bip32::ExtendedPrivKey;
use std::convert::TryFrom;
use crate::error::VaultError;
use secp256k1::PublicKey;
use crate::convert::error::ConversionError;

/// Fixed bytes number to represent `Address`
pub const ETHEREUM_ADDRESS_BYTES: usize = 20;

/// Account address (20 bytes)
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct EthereumAddress(pub [u8; ETHEREUM_ADDRESS_BYTES]);

impl EthereumAddress {
    /// Try to convert a byte vector to `Address`.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice with `ADDRESS_BYTES` length
    ///
    /// # Example
    ///
    /// ```
    /// let addr = emerald_vault::blockchain::EthereumAddress::try_from(&[0u8; emerald_vault::blockchain::ETHEREUM_ADDRESS_BYTES]).unwrap();
    /// assert_eq!(addr.to_string(), "0x0000000000000000000000000000000000000000");
    /// ```
    pub fn try_from(data: &[u8]) -> Result<Self, ConversionError> {
        if data.len() != ETHEREUM_ADDRESS_BYTES {
            return Err(ConversionError::InvalidLength);
        }

        Ok(EthereumAddress(to_arr(data)))
    }
}

impl ops::Deref for EthereumAddress {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; ETHEREUM_ADDRESS_BYTES]> for EthereumAddress {
    fn from(bytes: [u8; ETHEREUM_ADDRESS_BYTES]) -> Self {
        EthereumAddress(bytes)
    }
}

impl AsRef<[u8]> for EthereumAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for EthereumAddress {
    type Err = ConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != ETHEREUM_ADDRESS_BYTES * 2 && !s.starts_with("0x") {
            return Err(ConversionError::InvalidLength);
        }

        let value = if s.starts_with("0x") {
            s.split_at(2).1
        } else {
            s
        };

        EthereumAddress::try_from(hex::decode(&value)?.as_slice())
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl TryFrom<ExtendedPrivKey> for EthereumPrivateKey {
    type Error = VaultError;

    fn try_from(value: ExtendedPrivKey) -> Result<Self, Self::Error> {
        EthereumPrivateKey::try_from(value.private_key.secret_bytes().as_ref())
            .map_err(|_| VaultError::InvalidPrivateKey)
    }
}

impl From<PublicKey> for EthereumAddress {
    fn from(value: PublicKey) -> Self {
        let hash = keccak256(&value.serialize_uncompressed()[1..] /* cut '04' */);
        EthereumAddress(to_arr(&hash[12..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_display_zero_address() {
        assert_eq!(
            EthereumAddress::default().to_string(),
            "0x0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn should_display_real_address() {
        let addr = EthereumAddress([
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
        let addr = EthereumAddress([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse::<EthereumAddress>()
                .unwrap(),
            addr
        );
    }

    #[test]
    fn should_parse_real_address_without_prefix() {
        let addr = EthereumAddress([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            "0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse::<EthereumAddress>()
                .unwrap(),
            addr
        );
    }

    #[test]
    fn should_catch_wrong_address_encoding() {
        assert!("0x___c045110b8dbf29765047380898919c5cb56f4"
            .parse::<EthereumAddress>()
            .is_err());
    }

    #[test]
    fn should_catch_wrong_address_insufficient_length() {
        assert!("0x0e7c045110b8dbf297650473808989"
            .parse::<EthereumAddress>()
            .is_err());
    }

    #[test]
    fn should_catch_wrong_address_excess_length() {
        assert!("0x0e7c045110b8dbf29765047380898919c5cb56f400000000"
            .parse::<EthereumAddress>()
            .is_err());
    }

    #[test]
    fn should_catch_wrong_address_prefix() {
        assert!("0_0e7c045110b8dbf29765047380898919c5cb56f4"
            .parse::<EthereumAddress>()
            .is_err());
    }

    #[test]
    fn should_catch_missing_address_prefix() {
        assert!("_".parse::<EthereumAddress>().is_err());
    }

    #[test]
    fn should_catch_empty_address_string() {
        assert!("".parse::<EthereumAddress>().is_err());
    }
}
