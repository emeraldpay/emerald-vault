//! # Account transaction

use super::{Address, Error, PrivateKey};
use super::util::{RLPList, WriteRLP, keccak256, KECCAK256_BYTES};

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
    pub fn to_raw(&self, pk: &PrivateKey) -> Result<Vec<u8>, Error> {
        let mut rlp = self.to_rlp();

        let val = pk.sign_hash(self.hash())?;
        let sig = Signature::from(val);

        rlp.push(&sig.r);
        rlp.push(&sig.s);
        rlp.push(&sig.v);

        let mut vec = Vec::new();
        rlp.write_rlp(&mut vec);
        Ok(vec)
    }

    fn hash(&self) -> [u8; KECCAK256_BYTES] {
        let mut vec = Vec::new();
        self.to_rlp().write_rlp(&mut vec);
        keccak256(&vec)
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
}

/// Transaction sign data (see Appendix F. "Signing Transactions" from Yellow Paper)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Signature {
    /// ‘recovery id’, a 1 byte value specifying the sign and finiteness of the curve point
    pub v: u8,

    /// ECDSA signature first point (0 < r < secp256k1n)
    pub r: [u8; 32],

    /// ECDSA signature second point (0 < s < secp256k1n ÷ 2 + 1)
    pub s: [u8; 32],
}

impl From<[u8; 64]> for Signature {
    fn from(data: [u8; 64]) -> Self {
        let mut sign = Signature::default();

        sign.v = data[63] /* parity */ + 27;
        sign.r.copy_from_slice(&data[0..32]);
        sign.s.copy_from_slice(&data[32..64]);

        sign
    }
}

impl From<Signature> for (u8, [u8; 32], [u8; 32]) {
    fn from(s: Signature) -> Self {
        (s.v, s.r, s.s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::tests::*;

    #[test]
    fn should_sign_transaction() {
        let tx = Transaction {
            nonce: 101,
            gas_limit: 100000,
            ..Default::default()
        };

        let res =
            tx.sign(&as_bytes("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"));

        assert!(res.is_ok());
        assert!(res.unwrap().len() > 32);
    }
}
