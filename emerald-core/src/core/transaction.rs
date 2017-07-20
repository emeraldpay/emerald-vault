//! # Account transaction

use super::{Address, Error, PrivateKey, Signature};
use super::util::{KECCAK256_BYTES, RLPList, WriteRLP, keccak256, trim_bytes};

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
    pub fn to_signed_raw(&self, pk: PrivateKey, chain: u8) -> Result<Vec<u8>, Error> {
        let sig = pk.sign_hash(self.hash(chain))?;
        Ok(self.raw_from_sig(chain, sig))
    }

    /// RLP packed signed transaction from provided `Signature`
    pub fn raw_from_sig(&self, chain: u8, mut sig: Signature) -> Vec<u8> {
        let mut rlp = self.to_rlp_raw();

        // [Simple replay attack protection](https://github.com/ethereum/eips/issues/155)
        sig.v += chain * 2 + 35 - 27;

        rlp.push(&[sig.v][..]);
        rlp.push(&sig.r[..]);
        rlp.push(&sig.s[..]);

        let mut vec = Vec::new();
        rlp.write_rlp(&mut vec);

        vec
    }

    /// RLP packed transaction
    pub fn to_rlp(&self) -> Vec<u8> {
        self.to_rlp_raw().into()
    }

    fn to_rlp_raw(&self) -> RLPList {
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

    fn hash(&self, chain: u8) -> [u8; KECCAK256_BYTES] {
        let mut rlp = self.to_rlp_raw();

        // [Simple replay attack protection](https://github.com/ethereum/eips/issues/155)
        rlp.push(&chain);
        rlp.push(&[][..]);
        rlp.push(&[][..]);

        let mut vec = Vec::new();
        rlp.write_rlp(&mut vec);
        keccak256(&vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_sign_transaction_for_mainnet() {
        let tx = Transaction {
            nonce: 0,
            gas_price: /* 21000000000 */
                to_32bytes("0000000000000000000000000000000\
                              0000000000000000000000004e3b29200"),
            gas_limit: 21000,
            to: Some("0x0000000000000000000000000000000012345678"
                    .parse::<Address>()
                    .unwrap()),
            value: /* 1 ETC */
                to_32bytes("00000000000000000000000000000000\
                              00000000000000000de0b6b3a7640000"),
            data: Vec::new(),
        };

        /*
        {
           "nonce":"0x00",
           "gasPrice":"0x04e3b29200",
           "gasLimit":"0x5208",
           "to":"0x0000000000000000000000000000000012345678",
           "value":"0x0de0b6b3a7640000",
           "data":"",
           "chainId":61
        }
        */

        let pk = PrivateKey(to_32bytes(
            "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
        ));

        assert_eq!(tx.to_signed_raw(pk, 61 /*MAINNET_ID*/).unwrap().to_hex(),
                   "f86d\
                   80\
                   8504e3b29200\
                   825208\
                   940000000000000000000000000000000012345678\
                   880de0b6b3a7640000\
                   80\
                   819e\
                   a0b17da8416f42d62192b07ff855f4a8e8e9ee1a2e920e3c407fd9a3bd5e388daa\
                   a0547981b617c88587bfcd924437f6134b0b75f4484042db0750a2b1c0ccccc597");
    }

    #[test]
    fn should_sign_transaction_for_testnet() {
        let tx = Transaction {
            nonce: 1048585,
            gas_price: /* 21000000000 */
            to_32bytes("00000000000000000000000000000\
                        000000000000000000000000004a817c800"),
            gas_limit: 21000,
            to: Some("0x163b454d1ccdd0a12e88341b12afb2c98044c599"
                .parse::<Address>()
                .unwrap()),
            value: /* 1 ETC */
            to_32bytes("000000000000000000000000000000\
                        00000000000000001e7751166579880000"),
            data: Vec::new(),
        };

        /*
        {
            "jsonrpc":"2.0","method":"emerald_signTransaction",
            "params":[{"from":"0xc0de379b51d582e1600c76dd1efee8ed024b844a",
            "passphrase":"1234567890",
            "to":"0x163b454d1ccdd0a12e88341b12afb2c98044c599",
            "gas":"0x5208",
            "gasPrice":"0x04a817c800",
            "value":"0x1e7751166579880000",
            "nonce":"0x100009"},
            {"chain":"morden"}],
            "id":11
         }'
         */

        let pk = PrivateKey(to_32bytes(
            "28b469dc4b039ff63fcd4cb708c668545e644cb25f21df6920aac20e4bc743f7",
        ));

        assert_eq!(tx.to_signed_raw(pk, 62 /*TESTNET_ID*/).unwrap().to_hex(),
                    "f871\
                    83\
                    100009\
                    85\
                    04a817c800\
                    82\
                    5208\
                    94\
                    163b454d1ccdd0a12e88341b12afb2c98044c599\
                    891e77511665\
                    79\
                    8800\
                    0080819fa0cc6cd05d41bbbeb71913bf403a09db118f22e4ed7ebf707fcfb483dd1cde\
                    d890a03c0a3985771bc0f10cf9fe85e3ea3c17132e3f09551eaedb8d2ae97cec3ad9f7");
    }

}
