/*
Copyright 2019 ETCDEV GmbH

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
//! # Module to generate private key from HD path
//! according to the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//!

use super::error::Error;
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::ChildNumber;
use bitcoin::util::bip32::ExtendedPrivKey;
use crate::core::{PrivateKey, PRIVATE_KEY_BYTES};
use crate::hdwallet::DERIVATION_INDEX_SIZE;
use regex::Regex;
use secp256k1::Secp256k1;
use std::ops;
use crate::util::to_bytes;
use std::convert::TryInto;
use std::string::ToString;

lazy_static! {
    static ref HD_PATH_RE: Regex = Regex::new(r#"^m(/[0-9]'?)+"#).unwrap();
}

/// HD path according to BIP32
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HDPath(pub Vec<ChildNumber>);

impl HDPath {
    /// Parse HD derivation path into `ChildNumber` array
    /// Accepting path in format specified by BIP32
    ///
    /// # Arguments:
    ///
    /// * path - path string
    ///
    pub fn try_from(path: &str) -> Result<Self, Error> {
        let mut res: Vec<ChildNumber> = vec![];

        if !HD_PATH_RE.is_match(path) {
            return Err(Error::HDWalletError("Invalid HD path format".to_string()));
        }

        let (_, raw) = path.split_at(2);
        for i in raw.split('/') {
            let mut s = i.to_string();

            let mut is_hardened = false;
            if s.ends_with('\'') {
                is_hardened = true;
                s.pop();
            }

            match s.parse::<u32>() {
                Ok(v) => {
                    if is_hardened {
                        res.push(ChildNumber::Hardened {
                            index: v
                        })
                    } else {
                        res.push(ChildNumber::Normal {
                            index: v
                        })
                    }
                }
                Err(e) => {
                    return Err(Error::HDWalletError(format!(
                        "Invalid HD path child index: {}",
                        e.to_string()
                    )))
                }
            };
        }

        Ok(HDPath(res))
    }

    pub fn from_bytes(path: &[u8]) -> Result<Self, Error> {
        if path.len() <= 1 || path.len() % 4 != 1 {
            return Err(Error::HDWalletError("HD Path is too short".to_string()));
        }
        let mut left = path.to_vec();
        let len = left.remove(0) as usize;
        if left.len() != len * 4 {
            return Err(Error::HDWalletError("Invalid HD path length".to_string()));
        }
        let mut res: Vec<ChildNumber> = vec![];
        let mut pos = 0;
        while left.len() > pos {
            let mut item_bytes: [u8; 4] = Default::default();
            item_bytes.copy_from_slice(&left[pos..pos+4]);
            pos += 4;
            let item = u32::from_be_bytes(item_bytes);
            if item >= 0x8000_0000 {
                res.push(ChildNumber::Hardened { index: item - 0x8000_0000 });
            } else {
                res.push(ChildNumber::Normal { index: item });
            }
        }

        Ok(HDPath(res))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.0.len() as u8);
        for item in &self.0 {
            let x = match item {
                ChildNumber::Hardened { index} => 0x8000_0000 + *index,
                ChildNumber::Normal { index } => *index
            };
            buf.extend(to_bytes(x as u64, 4));
        }
        buf
    }
}

impl ops::Deref for HDPath {
    type Target = [ChildNumber];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::string::ToString for HDPath {
    fn to_string(&self) -> String {
        let mut buf = String::with_capacity(20);
        buf.push('m');
        for item in &self.0 {
            buf.push('/');
            match item {
                ChildNumber::Hardened{ index} => {
                    buf.push_str(&index.to_string());
                    buf.push('\'');
                },
                ChildNumber::Normal { index} => {
                    buf.push_str(&index.to_string());
                }
            }
        }
        buf
    }

}

/// Generate `PrivateKey` using BIP32
///
///  # Arguments:
///
///  * path - key derivation path
///  * seed - seed data for master node
///
pub fn generate_key(path: &HDPath, seed: &[u8]) -> Result<PrivateKey, Error> {
    let secp = Secp256k1::new();
    let sk = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
        .and_then(|k| k.derive_priv(&secp, &path.0))?;
    let key = PrivateKey::try_from(&sk.private_key.key[0..PRIVATE_KEY_BYTES])?;

    Ok(key)
}

/// Parse HD path into byte array
///
/// # Arguments:
///
/// * hd_str - path string
///
#[deprecated]
pub fn path_to_arr(hd_str: &str) -> Result<Vec<u8>, Error> {
    if !HD_PATH_RE.is_match(hd_str) {
        return Err(Error::HDWalletError(format!(
            "Invalid `hd_path` format: {}",
            hd_str
        )));
    }

    let (_, p) = hd_str.split_at(2);
    let mut buf = Vec::new();
    {
        let mut parse = |s: &str| {
            let mut str = s.to_string();
            let mut v: u64 = 0;

            if str.ends_with('\'') {
                v += 0x8000_0000;
                str.remove(s.len() - 1);
            }
            match str.parse::<u64>() {
                Ok(d) => v += d,
                Err(_) => return Err(Error::HDWalletError(format!("Invalid index: {}", hd_str))),
            }
            buf.extend(to_bytes(v, 4));
            Ok(())
        };

        for val in p.split('/') {
            parse(val)?;
        }
    }

    Ok(buf)
}

/// Parse HD path into byte array
/// prefixed with count of derivation indexes
pub fn to_prefixed_path(hd_str: &str) -> Result<Vec<u8>, Error> {
    let v = path_to_arr(hd_str)?;
    let count = (v.len() / DERIVATION_INDEX_SIZE) as u8;
    let mut buf = Vec::with_capacity(v.len() + 1);

    buf.push(count);
    buf.extend(v);

    Ok(buf)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core::Address;
    use hex::FromHex;
    use std::str::FromStr;

    #[test]
    fn parse_hdpath() {
        let parsed = HDPath::try_from("m/44'/60'/160720'/0'").unwrap();
        let exp = HDPath(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(60).unwrap(),
            ChildNumber::from_hardened_idx(160720).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);

        assert_eq!(parsed, exp)
    }

    #[test]
    fn create_from_bytes() {
        let path: [u8; 21] = [
            5,
            0x80, 0, 0, 44,
            0x80, 0, 0, 60,
            0x80, 0x02, 0x73, 0xd0,
            0x80, 0, 0, 0,
            0, 0, 0, 0,
        ];

        let parsed = HDPath::from_bytes(&path).unwrap();
        let exp = HDPath(vec![
            ChildNumber::Hardened { index: 44 },
            ChildNumber::Hardened { index: 60 },
            ChildNumber::Hardened { index: 160720 },
            ChildNumber::Hardened { index: 0 },
            ChildNumber::Normal { index: 0 }
        ]);

        assert_eq!(parsed, exp)
    }

    #[test]
    fn convert_to_bytes_zero() {
        let exp: [u8; 21] = [
            5,
            0x80, 0, 0, 44,
            0x80, 0, 0, 60,
            0x80, 0x02, 0x73, 0xd0,
            0x80, 0, 0, 0,
            0, 0, 0, 0,
        ];

        let parsed = HDPath::try_from("m/44'/60'/160720'/0'/0").unwrap();
        assert_eq!(parsed.to_bytes(), exp)
    }

    #[test]
    fn convert_to_bytes_zero_normal() {
        let exp: [u8; 21] = [
            5,
            0x80, 0, 0, 44,
            0x80, 0, 0, 60,
            0x80, 0x02, 0x73, 0xd0,
            0, 0, 0, 0,
            0, 0, 0, 0,
        ];

        let parsed = HDPath::try_from("m/44'/60'/160720'/0/0").unwrap();
        assert_eq!(parsed.to_bytes(), exp)
    }

    #[test]
    fn convert_to_bytes_some() {
        let exp: [u8; 21] = [
            5,
            0x80, 0, 0, 44,
            0x80, 0, 0, 60,
            0x80, 0x02, 0x73, 0xd0,
            0x80, 0, 0, 0,
            0, 0, 0x02, 0x45,
        ];

        let parsed = HDPath::try_from("m/44'/60'/160720'/0'/581").unwrap();
        assert_eq!(parsed.to_bytes(), exp)
    }

    #[test]
    fn convert_to_bytes_eth() {
        let exp: [u8; 21] = [
            5,
            0x80, 0, 0, 44,
            0x80, 0, 0, 60,
            0x80, 0, 0, 0,
            0x80, 0, 0, 0,
            0, 0, 0, 1,
        ];

        let parsed = HDPath::try_from("m/44'/60'/0'/0'/1").unwrap();
        assert_eq!(parsed.to_bytes(), exp)
    }

    #[test]
    fn convert_to_bytes_music() {
        let exp: [u8; 21] = [
            5,
            0x80, 0, 0, 44,
            0x80, 0, 0, 184,
            0x80, 0, 0, 0,
            0x80, 0, 0, 0,
            0, 0, 0, 17,
        ];

        let parsed = HDPath::try_from("m/44'/184'/0'/0'/17").unwrap();
        assert_eq!(parsed.to_bytes(), exp)
    }

    #[test]
    fn to_string_hdpath() {
        let parsed = HDPath::try_from("m/44'/60'/160720'/0'").unwrap();
        assert_eq!(parsed.to_string(), "m/44'/60'/160720'/0'");

        let parsed = HDPath::try_from("m/44'/60'/0'/0'").unwrap();
        assert_eq!(parsed.to_string(), "m/44'/60'/0'/0'");

        let parsed = HDPath::try_from("m/44'/60'/0'/0'/0").unwrap();
        assert_eq!(parsed.to_string(), "m/44'/60'/0'/0'/0");

        let parsed = HDPath::try_from("m/44'/60'/0'/0'/1").unwrap();
        assert_eq!(parsed.to_string(), "m/44'/60'/0'/0'/1");
    }

    #[test]
    fn test_key_generation() {
        let seed = Vec::from_hex("b15509eaa2d09d3efd3e006ef42151b3\
            0367dc6e3aa5e44caba3fe4d3e352e65\
            101fbdb86a96776b91946ff06f8eac59\
            4dc6ee1d3e82a42dfe1b40fef6bcc3fd").unwrap();

        let path = vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(60).unwrap(),
            ChildNumber::from_hardened_idx(160720).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
        ];

        let priv_key = generate_key(&HDPath(path), &seed).unwrap();
        assert_eq!(
            Address::from_str("0x79B9E1af57Ebb2600a134e28eA05e52A312957A6").unwrap(),
            priv_key.to_address()
        );
    }

    #[test]
    fn test_key_generation_eth() {
        let seed = Vec::from_hex("b016ba229b339e148dd72843a8423499ade5ddee29d3d1eb18315\
        516661c63a3e700fb4b995a7173ad0987ffcec7aa1ddb6bbdd2d2299b9ed23cce5d514b4986").unwrap();

        let path = vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(60).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_normal_idx(1).unwrap(),
        ];

        let priv_key = generate_key(&HDPath(path), &seed).unwrap();
        assert_eq!(
            Address::from_str("0x7545D615643F933c34C3E083E68CC831167F31af").unwrap(),
            priv_key.to_address()
        );
    }
}
