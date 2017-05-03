//! # Account transaction

use super::{Address, Error, PrivateKey};
use super::util::{KECCAK256_BYTES, RLPList, WriteRLP, keccak256};
use serde_json;

/// Transaction data
#[derive(Clone, Debug, Default)]
pub struct Transaction<'a> {
    /// Nonce
    pub nonce: u64,

    /// Gas Price
    pub gas_price: [u8; 32],

    /// Gas Limit
    pub gas_limit: u64,

    /// Target address, or None to create contract
    pub to: Option<Address>,

    /// Value transferred with transaction
    pub value: [u8; 32],

    /// Data transferred with transaction
    pub data: &'a [u8],
}

impl<'a> Transaction<'a> {
    /// Sign transaction data with provided private key
    pub fn to_signed_raw(&self, pk: PrivateKey) -> Result<Vec<u8>, Error> {
        let mut rlp = self.to_rlp();

        let sig = pk.sign_hash(self.hash())?;

        rlp.push(&sig.v);
        rlp.push(&sig.r.to_vec());
        rlp.push(&sig.s.to_vec());

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
    #[ignore]
    fn should_sign_transaction() {
        let empty = [];
        let tx = Transaction {
            nonce: 0,
            gas_price: /* 21000000000 */
                to_32bytes("00000000000000000000000000000000000000000000000000000004e3b29200"),
            gas_limit: 21000,
            to: Some("0x13978aee95f38490e9769c39b2773ed763d9cd5f"
                    .parse::<Address>()
                    .unwrap()),
            value: /* 1 ETC */
                to_32bytes("0000000000000000000000000000000000000000000000000de0b6b3a7640000"),
            data: &empty,
        };

        let pk = PrivateKey(
            to_32bytes("c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4"));

        assert_eq!(tx.to_signed_raw(pk).unwrap().to_hex(),
                   "f86d808504e3b292008252089413978aee95f38490e9769c39b2773ed763d9cd\
                    5f880de0b6b3a764000080819da00b5534f62bdb75adb28d3940838521d932cf\
                    3f968e39b3c8bc7d9dc829e6e0f7a05aab73ca44d2d3b8f5c3568cae9cc3e652e\
                    1441d3c6a2942eb00a48f660ddc79");
    }
}
