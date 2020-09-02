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
//! # Account ECDSA signatures using the SECG curve secp256k1

use crate::util::{keccak256, to_arr, KECCAK256_BYTES};
use super::EthereumAddress;
use super::super::Error;
use hex;
use rand::{rngs::OsRng, Rng};
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::{Message, Secp256k1, SignOnly};
use std::{fmt, ops, str};

/// Private key length in bytes
pub const PRIVATE_KEY_BYTES: usize = 32;

/// ECDSA crypto signature length in bytes
pub const ECDSA_SIGNATURE_BYTES: usize = 65;

lazy_static! {
    static ref ECDSA: Secp256k1<SignOnly> = Secp256k1::signing_only();
}

/// Transaction sign data (see Appendix F. "Signing Transactions" from Yellow Paper)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EthereumSignature {
    /// ‘recovery id’, a 1 byte value specifying the sign and finiteness of the curve point
    pub v: u8,

    /// ECDSA signature first point (0 < r < secp256k1n)
    pub r: [u8; 32],

    /// ECDSA signature second point (0 < s < secp256k1n ÷ 2 + 1)
    pub s: [u8; 32],
}

impl From<[u8; ECDSA_SIGNATURE_BYTES]> for EthereumSignature {
    fn from(data: [u8; ECDSA_SIGNATURE_BYTES]) -> Self {
        let mut sign = EthereumSignature::default();

        sign.v = data[0];
        sign.r.copy_from_slice(&data[1..(1 + 32)]);
        sign.s.copy_from_slice(&data[(1 + 32)..(1 + 32 + 32)]);

        sign
    }
}

impl Into<(u8, [u8; 32], [u8; 32])> for EthereumSignature {
    fn into(self) -> (u8, [u8; 32], [u8; 32]) {
        (self.v, self.r, self.s)
    }
}

impl Into<String> for EthereumSignature {
    fn into(self) -> String {
        format!(
            "0x{:X}{}{}",
            self.v,
            hex::encode(self.r),
            hex::encode(self.s)
        )
    }
}

/// Private key used as x in an ECDSA signature
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct EthereumPrivateKey(pub [u8; PRIVATE_KEY_BYTES]);

impl EthereumPrivateKey {
    /// Generate a new `PrivateKey` at random (`rand::OsRng`)
    pub fn gen() -> Self {
        Self::gen_custom(&mut OsRng::new().expect("Randomness is not ready"))
    }

    /// Generate a new `PrivateKey` with given custom random generator
    pub fn gen_custom<R: Rng + ?Sized>(rng: &mut R) -> Self {
        EthereumPrivateKey::from(SecretKey::new(rng))
    }

    /// Try to convert a byte slice into `PrivateKey`.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice with `PRIVATE_KEY_BYTES` length
    ///
    /// # Example
    ///
    /// ```
    /// const PKB: usize = emerald_vault::PRIVATE_KEY_BYTES;
    /// let pk = emerald_vault::EthereumPrivateKey::try_from(&[0u8; PKB]).unwrap();
    /// assert_eq!(pk.to_string(),
    ///            "0x0000000000000000000000000000000000000000000000000000000000000000");
    /// ```
    pub fn try_from(data: &[u8]) -> Result<Self, Error> {
        if data.len() != PRIVATE_KEY_BYTES {
            return Err(Error::InvalidLength(data.len()));
        }

        Ok(EthereumPrivateKey(to_arr(data)))
    }

    /// Extract `Address` from current private key.
    pub fn to_address(self) -> EthereumAddress {
        let key = PublicKey::from_secret_key(&ECDSA, &self.into());
        let hash = keccak256(&key.serialize_uncompressed()[1..] /* cut '04' */);
        EthereumAddress(to_arr(&hash[12..]))
    }

    /// Sign message
    pub fn sign_message(&self, msg: &str) -> Result<EthereumSignature, Error> {
        self.sign_hash(message_hash(msg))
    }

    /// Sign a slice of bytes
    pub fn sign_bytes(&self, data: &[u8]) -> Result<EthereumSignature, Error> {
        self.sign_hash(bytes_hash(data))
    }

    /// Sign hash from message (Keccak-256)
    pub fn sign_hash(&self, hash: [u8; KECCAK256_BYTES]) -> Result<EthereumSignature, Error> {
        let msg = Message::from_slice(&hash)?;
        let key = SecretKey::from_slice(self)?;

        let s = ECDSA.sign_recoverable(&msg, &key);
        let (rid, sig) = s.serialize_compact();

        let mut buf = [0u8; ECDSA_SIGNATURE_BYTES];
        buf[0] = (rid.to_i32() + 27) as u8;
        buf[1..65].copy_from_slice(&sig[0..64]);

        Ok(EthereumSignature::from(buf))
    }
}

impl ops::Deref for EthereumPrivateKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; PRIVATE_KEY_BYTES]> for EthereumPrivateKey {
    fn from(bytes: [u8; PRIVATE_KEY_BYTES]) -> Self {
        EthereumPrivateKey(bytes)
    }
}

impl From<SecretKey> for EthereumPrivateKey {
    fn from(key: SecretKey) -> Self {
        EthereumPrivateKey(to_arr(&key[0..PRIVATE_KEY_BYTES]))
    }
}

impl Into<SecretKey> for EthereumPrivateKey {
    fn into(self) -> SecretKey {
        SecretKey::from_slice(&self).expect("Expect secret key")
    }
}

impl str::FromStr for EthereumPrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != PRIVATE_KEY_BYTES * 2 && !s.starts_with("0x") {
            return Err(Error::InvalidHexLength(s.to_string()));
        }

        let value = if s.starts_with("0x") {
            s.split_at(2).1
        } else {
            s
        };

        EthereumPrivateKey::try_from(hex::decode(&value)?.as_slice())
    }
}

impl fmt::Display for EthereumPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

fn message_hash(msg: &str) -> [u8; KECCAK256_BYTES] {
    bytes_hash(msg.as_bytes())
}

fn bytes_hash(data: &[u8]) -> [u8; KECCAK256_BYTES] {
    let mut v = prefix(data).into_bytes();
    v.extend_from_slice(data);
    keccak256(&v)
}

/// [internal/ethapi: add personal sign method](https://github.com/ethereum/go-ethereum/pull/2940)
fn prefix(data: &[u8]) -> String {
    format!("\x19Ethereum Signed Message:\x0a{}", data.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;

    #[test]
    fn should_convert_into_address() {
        let key = EthereumPrivateKey(to_32bytes(
            "00b413b37c71bfb92719d16e28d7329dea5befa0d0b8190742f89e55617991cf",
        ));

        assert_eq!(
            key.to_address().to_string(),
            "0x3f4e0668c20e100d7c2a27d4b177ac65b2875d26"
        );
    }

    #[test]
    fn should_sign_hash() {
        let key = EthereumPrivateKey(to_32bytes(
            "3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1",
        ));

        let s = key
            .sign_hash(to_32bytes(
                "82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28",
            ))
            .unwrap();

        assert_eq!(s.v, 27);
        assert_eq!(
            s.r,
            to_32bytes("99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9",)
        );
        assert_eq!(
            s.s,
            to_32bytes("129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66",)
        );
    }

    #[test]
    fn should_calculate_message_hash() {
        assert_eq!(
            message_hash("Hello world"),
            to_32bytes("8144a6fa26be252b86456491fbcd43c1de7e022241845ffea1c3df066f7cfede",)
        );
    }
}
