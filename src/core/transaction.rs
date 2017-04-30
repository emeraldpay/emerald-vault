//! # Account transaction

use super::{Address, Error, PrivateKey};
use super::util::{KECCAK256_BYTES, RLPList, WriteRLP, keccak256};

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

        let sig = pk.sign_hash(self.hash())?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_sign_transaction() {
        let tx = Transaction {
            nonce: 101,
            gas_limit: 100000,
            ..Default::default()
        };

        let pk = PrivateKey(
            to_32bytes("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"));

        let res = tx.to_raw(&pk);

        assert!(res.is_ok());
        assert!(res.unwrap().len() > 32);
    }
}
