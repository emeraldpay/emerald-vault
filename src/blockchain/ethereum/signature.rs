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

use super::{EthereumAddress};
use crate::{convert::error::ConversionError, error::VaultError, trim_bytes, util::{keccak256, to_arr, KECCAK256_BYTES}};
use hex;
use rand::{rngs::OsRng, Rng};
use secp256k1::{
    PublicKey, SecretKey,
    Message,
    Secp256k1,
    SignOnly,
};
use std::{convert::TryFrom, fmt, ops, str};
use std::str::FromStr;
use rlp::RlpStream;
use crate::chains::EthereumChainId;
use crate::ethereum::hex::EthereumHex;

/// Private key length in bytes
pub const PRIVATE_KEY_BYTES: usize = 32;

/// ECDSA crypto signature length in bytes
pub const ECDSA_SIGNATURE_BYTES: usize = 65;

lazy_static! {
    static ref ECDSA: Secp256k1<SignOnly> = Secp256k1::signing_only();
}

/// Transaction sign data (see Appendix F. "Signing Transactions" from Yellow Paper)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EthereumBasicSignature {
    /// ‘recovery id’, a 1 byte value specifying the sign and finiteness of the curve point
    pub v: u8,

    /// ECDSA signature first point (0 < r < secp256k1n)
    pub r: [u8; 32],

    /// ECDSA signature second point (0 < s < secp256k1n ÷ 2 + 1)
    pub s: [u8; 32],
}

///
/// Signature for EIP-2930 type of transactions
///
/// See: https://eips.ethereum.org/EIPS/eip-2930
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EthereumEIP2930Signature {
    /// Y-coord bit on the curve
    pub y_parity: u8,

    /// ECDSA signature first point (0 < r < secp256k1n)
    pub r: [u8; 32],

    /// ECDSA signature second point (0 < s < secp256k1n ÷ 2 + 1)
    pub s: [u8; 32],
}

pub trait EthereumSignature {
    ///
    /// Append the signature to an rlp-encoded transaction
    fn append_to_rlp(&self, chain: EthereumChainId, rlp: &mut RlpStream);
}

impl EthereumSignature for EthereumBasicSignature {
    fn append_to_rlp(&self, chain_id: EthereumChainId, rlp: &mut RlpStream) {
        let mut v = u16::from(self.v);
        // [Simple replay attack protection](https://github.com/ethereum/eips/issues/155)
        // Can be already applied by HD wallet.
        // TODO: refactor to avoid this check
        let stamp = u16::from(chain_id.as_chainid() * 2 + 35 - 27);
        if v + stamp <= 0xff {
            v += stamp;
        }

        rlp.append(&(v as u8));
        rlp.append(&trim_bytes(&self.r[..]));
        rlp.append(&trim_bytes(&self.s[..]));
    }
}

impl EthereumSignature for EthereumEIP2930Signature {
    fn append_to_rlp(&self, _chain: EthereumChainId, rlp: &mut RlpStream) {
        rlp.append(&self.y_parity);
        rlp.append(&trim_bytes(&self.r[..]));
        rlp.append(&trim_bytes(&self.s[..]));
    }
}

impl From<[u8; ECDSA_SIGNATURE_BYTES]> for EthereumBasicSignature {
    fn from(data: [u8; ECDSA_SIGNATURE_BYTES]) -> Self {
        let mut sign = EthereumBasicSignature::default();
        sign.v = data[0];
        sign.r.copy_from_slice(&data[1..(1 + 32)]);
        sign.s.copy_from_slice(&data[(1 + 32)..(1 + 32 + 32)]);
        sign
    }
}

impl Into<(u8, [u8; 32], [u8; 32])> for EthereumBasicSignature {
    fn into(self) -> (u8, [u8; 32], [u8; 32]) {
        (self.v, self.r, self.s)
    }
}

impl ToString for EthereumBasicSignature {
    fn to_string(&self) -> String {
        format!(
            "0x{}{}{:x}",
            hex::encode(self.r),
            hex::encode(self.s),
            self.v,
        )
    }
}

impl FromStr for EthereumBasicSignature {
    type Err = VaultError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let encoded = EthereumHex::decode(s)?;
        if encoded.len() != 32 + 32 + 1 {
            return Err(VaultError::InvalidDataError("Invalid length".to_string()))
        }
        let r = to_arr(&encoded[0..32]);
        let s = to_arr(&encoded[32..64]);
        let v = encoded[64];
        let signature = EthereumBasicSignature {
            v,
            r,
            s
        };
        Ok(signature)
    }
}

/// Private key used as x in an ECDSA signature
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct EthereumPrivateKey(pub [u8; PRIVATE_KEY_BYTES]);

impl EthereumPrivateKey {
    /// Generate a new `PrivateKey` at random (`rand::OsRng`)
    pub fn gen() -> Self {
        Self::gen_custom(&mut OsRng::default())
    }

    /// Generate a new `PrivateKey` with given custom random generator
    pub fn gen_custom<R: Rng + ?Sized>(rng: &mut R) -> Self {
        EthereumPrivateKey::from(SecretKey::new(rng))
    }

    /// Extract `Address` from current private key.
    pub fn to_address(self) -> EthereumAddress {
        let key = PublicKey::from_secret_key(&ECDSA, &self.into());
        EthereumAddress::from(key)
    }

    pub fn sign<S>(&self, data: &dyn SignableHash) -> Result<S, VaultError>
        where S: SignatureMaker<S> {
        let hash = data.hash()?;
        self.sign_hash(hash)
    }

    /// Sign hash from message (Keccak-256)
    pub fn sign_hash<S>(&self, hash: [u8; KECCAK256_BYTES]) -> Result<S, VaultError> where S: SignatureMaker<S> {
        let msg = Message::from_slice(&hash)?;
        let key = SecretKey::from_slice(self)?;

        S::sign(msg, key)
    }
}

pub trait SignatureMaker<T> {
    fn sign(msg: Message, sk: SecretKey) -> Result<T, VaultError>;
}

///
/// For structures that can be signed. Those structure must be able to provide a bytes array that can be signed
pub trait Signable {

    ///
    /// Produce a bytes array that can be signed. Note it's not the hash in the most cases, but a source message
    /// before applying a hash which is a signature input.
    fn as_sign_message(&self) -> Vec<u8>;
}

///
/// To produce an Ethereum hash (Keccak256)
pub trait SignableHash {
    fn hash(&self) -> Result<[u8; KECCAK256_BYTES], VaultError>;
}

///
/// Standard implementation for any Signable structure
impl<T: ?Sized + Signable>  SignableHash for T {
    fn hash(&self) -> Result<[u8; KECCAK256_BYTES], VaultError> {
        let value = self.as_sign_message();
        let hash = keccak256(value.as_slice());
        Ok(hash)
    }
}

impl SignatureMaker<EthereumBasicSignature> for EthereumBasicSignature {
    fn sign(msg: Message, sk: SecretKey) -> Result<EthereumBasicSignature, VaultError> {
        let s = ECDSA.sign_ecdsa_recoverable(&msg, &sk);
        let (rid, sig) = s.serialize_compact();

        let mut buf = [0u8; ECDSA_SIGNATURE_BYTES];
        buf[0] = (rid.to_i32() + 27) as u8;
        buf[1..65].copy_from_slice(&sig[0..64]);

        Ok(EthereumBasicSignature::from(buf))
    }
}

impl SignatureMaker<EthereumEIP2930Signature> for EthereumEIP2930Signature {
    fn sign(msg: Message, sk: SecretKey) -> Result<EthereumEIP2930Signature, VaultError> {
        let s = ECDSA.sign_ecdsa_recoverable(&msg, &sk);
        let (rid, sig) = s.serialize_compact();

        let mut buf = [0u8; ECDSA_SIGNATURE_BYTES];
        buf[0] = (rid.to_i32() + 27) as u8;
        buf[1..65].copy_from_slice(&sig[0..64]);

        let mut r = [0u8; 32];
        r.copy_from_slice(&sig[0..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..64]);

        let sig = EthereumEIP2930Signature {
            y_parity: rid.to_i32() as u8,
            r, s
        };

        if sig.y_parity > 1 {
            // technically it's y-coord side, so can have only two possible values.
            // if we've got something different we did something completely wrong
            panic!("y_parity can be only 0 or 1. Found: {:}", sig.y_parity)
        }

        Ok(sig)
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

impl TryFrom<&[u8]> for EthereumPrivateKey {
    type Error = VaultError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != PRIVATE_KEY_BYTES {
            return Err(VaultError::InvalidPrivateKey);
        }

        Ok(EthereumPrivateKey(to_arr(value)))
    }
}

impl str::FromStr for EthereumPrivateKey {
    type Err = VaultError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != PRIVATE_KEY_BYTES * 2 && !s.starts_with("0x") {
            return Err(VaultError::ConversionError(ConversionError::InvalidLength));
        }
        let value = EthereumHex::decode(s)?;
        EthereumPrivateKey::try_from(value.as_slice())
    }
}

impl fmt::Display for EthereumPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", EthereumHex::encode(self.0))
    }
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
            .sign_hash::<EthereumBasicSignature>(to_32bytes(
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
    fn encode_decode_signature_to_string() {
        let key = EthereumPrivateKey(to_32bytes(
            "3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1",
        ));

        let s = key
            .sign_hash::<EthereumBasicSignature>(to_32bytes(
                "82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28",
            ))
            .unwrap();

        let encoded = s.to_string();
        let decoded = EthereumBasicSignature::from_str(encoded.as_str()).unwrap();

        assert_eq!(decoded, s);
    }

    #[test]
    fn decode_signature_from_string() {
        let encoded = "0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca661b";
        let s = EthereumBasicSignature::from_str(encoded).unwrap();

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
    fn sign_eip2930() {
        let key = to_32bytes(
            "4646464646464646464646464646464646464646464646464646464646464646",
        );
        let hash = to_32bytes("57c3588c6ef4be66e68464a5364cef58fe154f57b2ff8d8d89909ac10cd0527b");
        let sig = EthereumEIP2930Signature::sign(
            Message::from_slice(hash.as_ref()).unwrap(), SecretKey::from_slice(key.as_ref()).unwrap()
        );
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        assert_eq!(sig.y_parity, 1);
        assert_eq!(hex::encode(sig.r), "38c8eb279a4b6c4b806258389e1b5906b28418e3eff9e0fc81173f54fa37a255");
        assert_eq!(hex::encode(sig.s), "3acaa2b6d5e4edb561b918b4cb49cf1dbae9972ca90df7af6364598353a2c125");
    }

    #[test]
    fn sign_eip2930_2() {
        let key = to_32bytes(
            "4646464646464646464646464646464646464646464646464646464646464646",
        );
        let hash = to_32bytes("aef1156bbd124793e5d76bdf9fe9464e9ef79f2432abbaf0385e57e8ae8e8d5c");
        let sig = EthereumEIP2930Signature::sign(
            Message::from_slice(hash.as_ref()).unwrap(), SecretKey::from_slice(key.as_ref()).unwrap()
        );
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        assert_eq!(sig.y_parity, 0);
        assert_eq!(hex::encode(sig.r), "b935047bf9b8464afec5bda917281610b2aaabd8de4b01d2eba6e876c934ca7a");
        assert_eq!(hex::encode(sig.s), "431b406eb13aefca05a0320c3595700b9375df6fac8cc8ec5603ac2e42af4894");
    }

    #[test]
    fn sign_eip2930_3() {
        let key = to_32bytes(
            "4646464646464646464646464646464646464646464646464646464646464646",
        );
        let hash = to_32bytes("68fe011ba5be4a03369d51810e7943abab15fbaf757f9296711558aee8ab772b");
        let sig = EthereumEIP2930Signature::sign(
            Message::from_slice(hash.as_ref()).unwrap(), SecretKey::from_slice(key.as_ref()).unwrap()
        );
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        assert_eq!(sig.y_parity, 1);
        assert_eq!(hex::encode(sig.r), "f0b3347ec48e78bf5ef6075b332334518ebc2f90d2bf0fea080623179936382e");
        assert_eq!(hex::encode(sig.s), "5c58c5beeafb2398d5e79b40b320421112a9672167f27e7fc55e76d2d7d11062");
    }

}
