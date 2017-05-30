//! # Account transaction

use super::{Address, Error, PrivateKey};
use super::util::{KECCAK256_BYTES, RLPList, WriteRLP, keccak256, trim_bytes};

// Main chain id
pub const _MAINNET_ID: u8 = 61;

// Test chain id
pub const TESTNET_ID: u8 = 62;

/// Transaction data
#[derive(Clone, Debug, Default)]
pub struct Transaction {
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
    pub data: Vec<u8>,
}

impl Transaction {
    /// Sign transaction data with provided private key
    pub fn to_signed_raw(&self, pk: PrivateKey) -> Result<Vec<u8>, Error> {
        let mut rlp = self.to_rlp();

        let mut sig = pk.sign_hash(self.hash())?;

        // [Simple replay attack protection](https://github.com/ethereum/eips/issues/155)
        sig.v += TESTNET_ID * 2 + 35 - 27;

        rlp.push(&[sig.v][..]);
        rlp.push(&sig.r[..]);
        rlp.push(&sig.s[..]);

        let mut vec = Vec::new();
        rlp.write_rlp(&mut vec);
        Ok(vec)
    }

    fn hash(&self) -> [u8; KECCAK256_BYTES] {
        let mut rlp = self.to_rlp();

        // [Simple replay attack protection](https://github.com/ethereum/eips/issues/155)
        rlp.push(&TESTNET_ID);
        rlp.push(&[][..]);
        rlp.push(&[][..]);

        let mut vec = Vec::new();
        rlp.write_rlp(&mut vec);
        keccak256(&vec)
    }

    fn to_rlp(&self) -> RLPList {
        let mut data = RLPList::default();

        data.push(&self.nonce);
        data.push(trim_bytes(&self.gas_price));
        data.push(&self.gas_limit);

        match self.to {
            Some(addr) => data.push(&Some(&addr[..])),
            _ => data.push::<Option<&[u8]>>(&None),
        };

        data.push(trim_bytes(&self.value));
        data.push(self.data.as_slice());

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

//    #[test]
//    fn should_sign_transaction_mainnet() {
//        let tx = Transaction {
//            nonce: 0,
//            gas_price: /* 21000000000 */
//                to_32bytes("00000000000000000000000000000000000000000000000000000004e3b29200"),
//            gas_limit: 21000,
//            to: Some("0x0000000000000000000000000000000012345678"
//                    .parse::<Address>()
//                    .unwrap()),
//            value: /* 1 ETC */
//                to_32bytes("0000000000000000000000000000000000000000000000000de0b6b3a7640000"),
//            data: Vec::new(),
//        };
//
//        /*
//        {
//           "nonce":"0x00",
//           "gasPrice":"0x04e3b29200",
//           "gasLimit":"0x5208",
//           "to":"0x0000000000000000000000000000000012345678",
//           "value":"0x0de0b6b3a7640000",
//           "data":"",
//           "chainId":61
//        }
//        */
//
//        let pk = PrivateKey(
//            to_32bytes("c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4"));
//
//        assert_eq!(tx.to_signed_raw(pk).unwrap().to_hex(),
//                   "f86d\
//                   80\
//                   8504e3b29200\
//                   825208\
//                   940000000000000000000000000000000012345678\
//                   880de0b6b3a7640000\
//                   80\
//                   819e\
//                   a0b17da8416f42d62192b07ff855f4a8e8e9ee1a2e920e3c407fd9a3bd5e388daa\
//                   a0547981b617c88587bfcd924437f6134b0b75f4484042db0750a2b1c0ccccc597");
//    }
//}
}