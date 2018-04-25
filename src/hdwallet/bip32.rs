//! # Module to generate private key from HD path
//! according to the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//!

use super::error::Error;
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::ChildNumber::{self, Hardened, Normal};
use bitcoin::util::bip32::ExtendedPrivKey;
use core::{PrivateKey, PRIVATE_KEY_BYTES};
use hdwallet::DERIVATION_INDEX_SIZE;
use regex::Regex;
use secp256k1::Secp256k1;
use std::ops;
use util::to_bytes;

lazy_static! {
    static ref HD_PATH_RE: Regex = Regex::new(r#"^m/{1}[^0-9'/]*"#).unwrap();
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
                        res.push(Hardened(v))
                    } else {
                        res.push(Normal(v))
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
}

impl ops::Deref for HDPath {
    type Target = [ChildNumber];

    fn deref(&self) -> &Self::Target {
        &self.0
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
    let sk = ExtendedPrivKey::new_master(&secp, Network::Bitcoin, seed)
        .and_then(|k| ExtendedPrivKey::from_path(&secp, &k, path))?;
    let key = PrivateKey::try_from(&sk.secret_key[0..PRIVATE_KEY_BYTES])?;

    Ok(key)
}

/// Parse HD path into byte array
///
/// # Arguments:
///
/// * hd_str - path string
///
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
    use core::Address;
    use hex::FromHex;
    use std::str::FromStr;

    #[test]
    fn parse_hdpath() {
        let parsed = HDPath::try_from("m/44'/60'/160720'/0'").unwrap();
        let exp = HDPath(vec![
            Hardened(44),
            Hardened(60),
            Hardened(160720),
            Hardened(0),
        ]);

        assert_eq!(parsed, exp)
    }

    #[test]
    fn test_key_generation() {
        let seed = Vec::from_hex("b15509eaa2d09d3efd3e006ef42151b3\
            0367dc6e3aa5e44caba3fe4d3e352e65\
            101fbdb86a96776b91946ff06f8eac59\
            4dc6ee1d3e82a42dfe1b40fef6bcc3fd").unwrap();

        let path = vec![
            Hardened(44),
            Hardened(60),
            Hardened(160720),
            Hardened(0),
            Normal(0),
        ];

        let priv_key = generate_key(&HDPath(path), &seed).unwrap();
        assert_eq!(
            Address::from_str("0x79B9E1af57Ebb2600a134e28eA05e52A312957A6").unwrap(),
            priv_key.to_address().unwrap()
        );
    }
}
