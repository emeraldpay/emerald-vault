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
//! # Module to generate private key from HD path
//! according to the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//!

use super::error::Error;
use crate::blockchain::{EthereumPrivateKey, PRIVATE_KEY_BYTES};
use bitcoin::{
    network::constants::Network,
    util::bip32::{DerivationPath, ExtendedPrivKey},
};
use hdpath::StandardHDPath;
use secp256k1::Secp256k1;


/// Generate `PrivateKey` using BIP32
///
///  # Arguments:
///
///  * path - key derivation path
///  * seed - seed data for master node
///
pub fn generate_key(path: &StandardHDPath, seed: &[u8]) -> Result<EthereumPrivateKey, Error> {
    let secp = Secp256k1::new();
    let sk = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
        .and_then(|k| k.derive_priv(&secp, &DerivationPath::from(path)))?;
    let key = EthereumPrivateKey::try_from(&sk.private_key.key[0..PRIVATE_KEY_BYTES])?;

    Ok(key)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::blockchain::EthereumAddress;
    use hdpath::Purpose;
    use hex::FromHex;
    use std::str::FromStr;

    #[test]
    fn test_key_generation() {
        let seed = Vec::from_hex(
            "b15509eaa2d09d3efd3e006ef42151b3\
             0367dc6e3aa5e44caba3fe4d3e352e65\
             101fbdb86a96776b91946ff06f8eac59\
             4dc6ee1d3e82a42dfe1b40fef6bcc3fd",
        )
            .unwrap();
        let path = StandardHDPath::new(Purpose::Pubkey, 60, 160720, 0, 0);

        let priv_key = generate_key(&path, &seed).unwrap();

        assert_eq!(
            priv_key.to_address(),
            EthereumAddress::from_str("0x1DD9cBeFBbC3284e9C3228793a560B4F0841Db6f").unwrap()
        );
    }

    #[test]
    fn test_key_generation_eth() {
        let seed = Vec::from_hex(
            "b016ba229b339e148dd72843a8423499ade5ddee29d3d1eb18315\
             516661c63a3e700fb4b995a7173ad0987ffcec7aa1ddb6bbdd2d2299b9ed23cce5d514b4986",
        )
        .unwrap();

        let path = StandardHDPath::new(Purpose::Pubkey, 60, 0, 1, 0);

        let priv_key = generate_key(&path, &seed).unwrap();
        assert_eq!(
            priv_key.to_address(),
            EthereumAddress::from_str("0x5d383cDB23983578131aD57f3F36Ab19ca6E6854").unwrap()
        );
    }
}
