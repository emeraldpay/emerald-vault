/*
Copyright 2022 EmeraldPay, Inc

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

//!
//! A basic Ethereum like signature to authenticate a plain text message.
//!
//! Used by `personal_sign` JSON RPC
//!
//! See:
//! - https://eips.ethereum.org/EIPS/eip-191
//!
//!

use crate::ethereum::signature::{Signable};

const PREFIX: &[u8] = "Ethereum Signed Message:\n".as_bytes();

///
/// EIP-191 type of a Signable message based on a string.
impl Signable for String {
    fn as_sign_message(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x19);
        buf.extend_from_slice(PREFIX);
        buf.extend_from_slice(self.len().to_string().as_bytes());
        buf.extend_from_slice(self.as_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use crate::ethereum::signature::{EthereumBasicSignature, Signable, SignableHash};
    use crate::{EthereumPrivateKey, to_32bytes};

    #[test]
    fn sign_test_1() {
        // test vector from Etherjar
        let pk = EthereumPrivateKey::from_str("0x4646464646464646464646464646464646464646464646464646464646464646").unwrap();
        let msg = "test-test-test".to_string();

        let signature = pk.sign::<EthereumBasicSignature>(&msg);
        assert!(signature.is_ok());

        assert_eq!(
            "0xc26a3a1922d97e573db507e82cbace7b57e54106cc96d598d29ac16aabe48153313302cb629b7307baae0ae5e74f68e58564615ccfde0d03603381e1a233e0ed1c".to_string(),
            signature.unwrap().to_string()
        )
    }

    #[test]
    fn sign_test_2() {
        // test vector from Etherjar
        let pk = EthereumPrivateKey::from_str("0x4646464646464646464646464646464646464646464646464646464646464646").unwrap();
        let msg = "test-test-test 2".to_string();

        let signature = pk.sign::<EthereumBasicSignature>(&msg);
        assert!(signature.is_ok());

        assert_eq!(
            "0x86f13303ffc5c05b3bf500f7f6f8bce9074721ea792e41c9f3624318ee08eebc6c1e4c3f091b2c9611361d462af3103c64a6873918c1aacaf2171bd36615f9f61c".to_string(),
            signature.unwrap().to_string()
        )
    }

    #[test]
    fn sign_test_3() {
        // test vector from Etherjar
        let pk = EthereumPrivateKey::from_str("0x4646464646464646464646464646464646464646464646464646464646464646").unwrap();
        let msg = "test-test-test 3".to_string();

        let signature = pk.sign::<EthereumBasicSignature>(&msg);
        assert!(signature.is_ok());

        assert_eq!(
            "0xb16541fb0a35a5415c9ddc59afd410b45af88c97e7ca7b172306e9513951279a64d8fc0e4efe055417e604244d53f538422f0b7c686c10133ebad1c91df2980d1b".to_string(),
            signature.unwrap().to_string()
        )
    }

    #[test]
    fn sign_test_4() {
        // test vector from Etherjar
        let pk = EthereumPrivateKey::from_str("0xb16541fb0a35a5415c9ddc59afd410b45af88c97e7ca7b172306e9513f538422").unwrap();
        let msg = "test b16541fb0a35a5415c9ddc59afd410b45af88c97e7ca7b172306e9513951279a64d8fc0e4efe055417e604244d53f538422f0b7c686c10133ebad1c91df2980d1b".to_string();

        let signature = pk.sign::<EthereumBasicSignature>(&msg);
        assert!(signature.is_ok());

        assert_eq!(
            "0xde8d65f0d3de2fbdac8f9348b7e215bcaa7780f772ed28e7d6cdae458938b86b51411b1d50af102484b3bbd4cc1b8ace1ecbcd0747fbbf303d10beb579d67e4b1c".to_string(),
            signature.unwrap().to_string()
        )
    }

    #[test]
    fn should_calculate_message_hash() {
        assert_eq!(
            (&"Hello world".to_string() as &dyn Signable).hash(),
            to_32bytes("8144a6fa26be252b86456491fbcd43c1de7e022241845ffea1c3df066f7cfede",)
        );
    }
}
