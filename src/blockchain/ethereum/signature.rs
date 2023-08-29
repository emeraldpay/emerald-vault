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
use num::ToPrimitive;
use rand::{rngs::OsRng, Rng};
use secp256k1::{
    PublicKey, SecretKey,
    Message,
    Secp256k1,
    All, ecdsa::{RecoverableSignature, RecoveryId},
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
    static ref ECDSA: Secp256k1<All> = Secp256k1::gen_new();
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

impl TryFrom<&EthereumBasicSignature> for RecoverableSignature {

    type Error = VaultError;

    fn try_from(value: &EthereumBasicSignature) -> Result<Self, Self::Error> {
        let rid = RecoveryId::from_i32(&value.v.to_i32().expect("not i32") - 27i32)
            .map_err(|_| VaultError::InvalidDataError("Invalid Signature RecID".to_string()))?;

        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(&value.r);
        buf[32..64].copy_from_slice(&value.s);

        RecoverableSignature::from_compact(&buf, rid)
            .map_err(|_| VaultError::InvalidDataError("Invalid Signature Data".to_string()))
    }

}

impl EthereumBasicSignature {

    ///
    /// Verify that the current signature is indeed produced by the specified `address` for the original `msg`.
    ///
    pub fn verify(&self, msg: &dyn SignableHash, address: &EthereumAddress) -> Result<bool, VaultError> {
        let act_address = self.extract_signer(msg)?;
        Ok(act_address == *address)
    }

    ///
    /// Extract the signer address which is produced the current signature (`self`) for the specified `msg`.
    /// Return error if the signature is invalid
    ///
    pub fn extract_signer(&self, msg: &dyn SignableHash) -> Result<EthereumAddress, VaultError> {
        let hash = msg.hash()?;
        let msg = Message::from_slice(&hash)?;
        let sig = RecoverableSignature::try_from(self)?;
        let pk = ECDSA.recover_ecdsa(&msg, &sig)?;
        Ok(EthereumAddress::from(pk))
    }

    ///
    /// Recover a signature with original `v` for a EIP-155 type of signature.
    /// Used to find a signature that can verify such EIP-155 transaction.
    pub fn recover_eip155(&self, chain_id: EthereumChainId) -> EthereumBasicSignature {
        if self.v == 27 || self.v == 28 {
            return  self.clone()
        }
        EthereumBasicSignature {
            v: self.v - chain_id.as_chainid() * 2 - 35 + 27,
            r: self.r,
            s: self.s,
        }
    }

    ///
    ///  Convert (or ensure) the signature to EIP-155 format which includes chain_id as part of the V
    pub fn to_eip155(&self, chain_id: EthereumChainId) -> EthereumBasicSignature {
        if self.v == 27 || self.v == 28 {
            EthereumBasicSignature {
                v: self.v + chain_id.as_chainid() * 2 + 35 - 27,
                r: self.r,
                s: self.s,
            }
        } else {
            // when it's already in EIP-155
            self.clone()
        }
    }

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
        rlp.append(&self.v);
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
        Ok(EthereumBasicSignature::from(s))
    }
}

impl SignatureMaker<EthereumEIP2930Signature> for EthereumEIP2930Signature {
    fn sign(msg: Message, sk: SecretKey) -> Result<EthereumEIP2930Signature, VaultError> {
        let s = ECDSA.sign_ecdsa_recoverable(&msg, &sk);
        Ok(EthereumEIP2930Signature::from(s))
    }
}

impl From<RecoverableSignature> for EthereumBasicSignature {
    fn from(value: RecoverableSignature) -> Self {
        let (rid, sig) = value.serialize_compact();

        let mut buf = [0u8; ECDSA_SIGNATURE_BYTES];
        buf[0] = (rid.to_i32() + 27) as u8;
        buf[1..65].copy_from_slice(&sig[0..64]);

        EthereumBasicSignature::from(buf)
    }
}

impl From<RecoverableSignature> for EthereumEIP2930Signature {
    fn from(value: RecoverableSignature) -> Self {
        let (rid, sig) = value.serialize_compact();

        let mut buf = [0u8; ECDSA_SIGNATURE_BYTES];
        buf[0] = (rid.to_i32() + 27) as u8;
        buf[1..65].copy_from_slice(&sig[0..64]);

        let mut r = [0u8; 32];
        r.copy_from_slice(&sig[0..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..64]);

        let y_parity = rid.to_i32() as u8;

        if y_parity > 1 {
            // technically it's y-coord side, so can have only two possible values.
            // if we've got something different we did something completely wrong
            panic!("y_parity can be only 0 or 1. Found: {:}", y_parity)
        }

        EthereumEIP2930Signature {
            y_parity,
            r, s
        }
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
    use num_bigint::BigUint;
    use crate::num::Zero;
    use crate::num::Num;

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

    #[test]
    fn convert_to_secp256k1_format() {
        let encoded = "0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca661b";
        let s = EthereumBasicSignature::from_str(encoded).unwrap();

        let converted = RecoverableSignature::try_from(&s);
        assert!(converted.is_ok());

        let back = EthereumBasicSignature::from(converted.unwrap());

        assert_eq!(encoded,back.to_string());
    }

    #[test]
    fn extract_legacy_tx_signature() {
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 1,
            gas_price: BigUint::from_str("10000000").unwrap(),
            gas_limit: 21_000,
            // self transction
            to: Some(EthereumAddress::from_str("0x3d66483b4cad3518861029ff86a387ebc4705172").unwrap()),
            value: BigUint::zero(),
            data: vec![],
        };

        let signature = EthereumBasicSignature::from_str("0x99a1d0271a0e3c3d2cd1f659b262675646653a0a3ca6adc6f1c3ec93a589572e39ea3005f6baaf56e03440254065cf5ae7020e7c31cdc3fbf305c7fbe262a3db26").unwrap();

        println!("signature v: {}", signature.v);
        let signature = signature.recover_eip155(EthereumChainId::Ethereum);
        println!("signature v: {}", signature.v);

        let from = signature.extract_signer(&tx);
        if !from.is_ok() {
            println!("{:}", from.clone().err().unwrap());
        }
        assert!(from.is_ok());
        assert_eq!(from.unwrap(), EthereumAddress::from_str("0x3d66483b4cad3518861029ff86a387ebc4705172").unwrap());
    }

    #[test]
    fn extract_legacy_tx_signature_existing_0a28d856() {
        // tx 0x0a28d856bb9e954d2c203c63b7b083c593815c21c62213b4be627a6e734ec60a
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 0xacb1b6,
            gas_price: BigUint::from_str_radix("2540be400", 16).unwrap(),
            gas_limit: 0xc350,
            to: Some(EthereumAddress::from_str("0x04356be552e55bedea0644ed945b44e2007217ef").unwrap()),
            value: BigUint::from_str_radix("1a82e6757100ed00", 16).unwrap(),
            data: vec![],
        };

        let signature = EthereumBasicSignature::from_str("0xa9df7f5f8bfbf89d6e255ffed87e98c0fe1814314e599bddcd6b857b76967f546f56f56d2490f877c6a682cad1e757270203c0c4cde8e6c78545ad619058790425").unwrap();

        println!("signature v: {}", signature.v);
        let signature = signature.recover_eip155(EthereumChainId::Ethereum);
        println!("signature v: {}", signature.v);

        let from = signature.extract_signer(&tx);
        if !from.is_ok() {
            println!("{:}", from.clone().err().unwrap());
        }
        assert!(from.is_ok());
        assert_eq!(from.unwrap(), EthereumAddress::from_str("0x52bc44d5378309ee2abf1539bf71de1b7d7be3b5").unwrap());
    }

    #[test]
    fn encode_eip155_signature() {
        let signature = EthereumBasicSignature {
            v: 0x26,
            r: to_32bytes("94b35e167d640006121ae3566fb877a8ed74a6e2d43160ed7abfa6571c0ce905"),
            s: to_32bytes("6bd8835d7c611bfa6f279b843a7dd2145109a12b8bdfc71e636b49fa6fa3c81c"),
        };

        let mut rlp = RlpStream::new();
        signature.append_to_rlp(EthereumChainId::Ethereum, &mut rlp);
        // rlp.finalize_unbounded_list();
        let act = rlp.out().to_vec();

        assert_eq!(hex::encode(act), "26a094b35e167d640006121ae3566fb877a8ed74a6e2d43160ed7abfa6571c0ce905a06bd8835d7c611bfa6f279b843a7dd2145109a12b8bdfc71e636b49fa6fa3c81c");
    }

    #[test]
    fn to_eip155_eth() {
        let signature = EthereumBasicSignature {
            v: 27,
            r: to_32bytes("94b35e167d640006121ae3566fb877a8ed74a6e2d43160ed7abfa6571c0ce905"),
            s: to_32bytes("6bd8835d7c611bfa6f279b843a7dd2145109a12b8bdfc71e636b49fa6fa3c81c"),
        };

        let eip155 = signature.to_eip155(EthereumChainId::Ethereum);
        assert_eq!(eip155.v, 27 + 2 + 35 - 27);

        let signature = EthereumBasicSignature {
            v: 28,
            r: to_32bytes("94b35e167d640006121ae3566fb877a8ed74a6e2d43160ed7abfa6571c0ce905"),
            s: to_32bytes("6bd8835d7c611bfa6f279b843a7dd2145109a12b8bdfc71e636b49fa6fa3c81c"),
        };

        let eip155 = signature.to_eip155(EthereumChainId::Ethereum);
        assert_eq!(eip155.v, 28 + 2 + 35 - 27);
    }

    #[test]
    fn to_eip155_etc() {
        let signature = EthereumBasicSignature {
            v: 27,
            r: to_32bytes("94b35e167d640006121ae3566fb877a8ed74a6e2d43160ed7abfa6571c0ce905"),
            s: to_32bytes("6bd8835d7c611bfa6f279b843a7dd2145109a12b8bdfc71e636b49fa6fa3c81c"),
        };

        let eip155 = signature.to_eip155(EthereumChainId::EthereumClassic);
        assert_eq!(eip155.v, 27 + 61 * 2 + 35 - 27);

        let signature = EthereumBasicSignature {
            v: 28,
            r: to_32bytes("94b35e167d640006121ae3566fb877a8ed74a6e2d43160ed7abfa6571c0ce905"),
            s: to_32bytes("6bd8835d7c611bfa6f279b843a7dd2145109a12b8bdfc71e636b49fa6fa3c81c"),
        };

        let eip155 = signature.to_eip155(EthereumChainId::EthereumClassic);
        assert_eq!(eip155.v, 28 + 61 * 2 + 35 - 27);
    }
}
