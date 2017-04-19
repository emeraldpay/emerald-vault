//! # Sign transaction

use super::{Address, PrivateKey};
use crypto::digest::Digest;
use crypto::sha3::{Sha3, Sha3Mode};
use rlp::{RLPList, WriteRLP};
use secp256k1::{ContextFlag, Error, Message, Secp256k1};
use secp256k1::key::SecretKey;

/// Transaction data
#[derive(Clone, Debug, Default)]
pub struct Transaction<'a> {
    /// Nonce
    pub nonce: u64,

    /// Gas Price
    pub gas_price: [u8; 32],

    /// Gas Limit
    pub gas_limit: u64,

    /// Source address
    pub from: Address,

    /// Target address, or None to create contract
    pub to: Option<Address>,

    /// Value transferred with transaction
    pub value: [u8; 32],

    /// Data transferred with transaction
    pub data: &'a [u8],
}

impl<'a> Transaction<'a> {
    /// Sign transaction data with provided private key
    pub fn sign(&self, pk: &PrivateKey) -> Result<Vec<u8>, Error> {
        let mut rlp = self.to_rlp();

        let s = (sign(&self.hash(), pk))?;
        let (v, r, s) = (TransactionSignature::from(s)).into();

        rlp.push(&r);
        rlp.push(&s);
        rlp.push(&v);

        let mut vec = Vec::new();
        rlp.write_rlp(&mut vec);
        Ok(vec)
    }

    fn to_rlp(&self) -> RLPList {
        let mut data = RLPList::default();

        data.push(&self.nonce);
        data.push(&self.gas_price.to_vec());
        data.push(&self.gas_limit);
        data.push(&self.to.map(|x| x.to_vec()));
        data.push(&self.value.to_vec());
        data.push(&self.data.to_vec());

        data
    }

    fn hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];

        let mut vec = Vec::new();
        self.to_rlp().write_rlp(&mut vec);

        let mut sha3 = Sha3::new(Sha3Mode::Keccak256);
        sha3.input(vec.as_slice());
        sha3.result(&mut hash);

        hash
    }
}

/// Transaction sign data (see Appendix F. "Signing Transactions" from Yellow Paper)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionSignature {
    /// ‘recovery id’, a 1 byte value specifying the sign and finiteness of the curve point
    pub v: u8,

    /// ECDSA signature first point (0 < r < secp256k1n)
    pub r: [u8; 32],

    /// ECDSA signature second point (0 < s < secp256k1n ÷ 2 + 1)
    pub s: [u8; 32],
}

impl From<[u8; 64]> for TransactionSignature {
    fn from(data: [u8; 64]) -> Self {
        let mut sign = TransactionSignature::default();

        sign.v = data[63] /* parity */ + 27;
        sign.r.copy_from_slice(&data[0..32]);
        sign.s.copy_from_slice(&data[32..64]);

        sign
    }
}

impl From<TransactionSignature> for (u8, [u8; 32], [u8; 32]) {
    fn from(s: TransactionSignature) -> Self {
        (s.v, s.r, s.s)
    }
}

/// Sign hashed message (32 bytes) with provide private key (32 bytes)
pub fn sign(hash: &[u8], pk: &PrivateKey) -> Result<[u8; 64], Error> {
    let signer = Secp256k1::with_caps(ContextFlag::SignOnly);
    let sk = (SecretKey::from_slice(&signer, pk))?;

    let msg = Message::from_slice(hash).expect("Expect valid hash message");
    let sign = (signer.sign_schnorr(&msg, &sk))?;

    let mut buf = [0u8; 64];
    buf.copy_from_slice(sign.serialize().as_slice());
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::{Transaction, sign};
    use rustc_serialize::hex::FromHex;

    fn as_32bytes(hex: &str) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&hex.from_hex().unwrap());
        buf
    }

    #[test]
    fn should_sign_transaction() {
        let tx = Transaction {
            nonce: 101,
            gas_limit: 100000,
            ..Default::default()
        };

        let res = tx.sign(
            &as_32bytes("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"));

        assert!(res.is_ok());
        assert!(res.unwrap().len() > 32);
    }

    #[test]
    fn should_sign_message_hash() {
        let hash = as_32bytes("1f483adb4a0f8c53d0ff8b6df23bbeae846815e7a52bac234edeaeb082b8d51a");
        let pk = as_32bytes("dcb2652ce3f3e46a57fd4814f926daefd6082c5cda44d35a6fd0f6da67ca256e");

        assert!(sign(&hash, &pk).is_ok());
    }
}
