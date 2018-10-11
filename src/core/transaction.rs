//! # Account transaction

use super::util::{keccak256, trim_bytes, RLPList, WriteRLP, KECCAK256_BYTES};
use super::{Address, Error, PrivateKey, Signature};

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
        Ok(self.raw_from_sig(chain, &sig))
    }

    /// RLP packed signed transaction from provided `Signature`
    pub fn raw_from_sig(&self, chain: u8, sig: &Signature) -> Vec<u8> {
        let mut rlp = self.to_rlp_raw(None);

        // [Simple replay attack protection](https://github.com/ethereum/eips/issues/155)
        // Can be already applied by HD wallet.
        // TODO: refactor to avoid this check
        let mut v = u16::from(sig.v);
        let stamp = u16::from(chain * 2 + 35 - 27);
        if v + stamp <= 0xff {
            v += stamp;
        }

        rlp.push(&(v as u8));
        rlp.push(&sig.r[..]);
        rlp.push(&sig.s[..]);

        let mut buf = Vec::new();
        rlp.write_rlp(&mut buf);

        buf
    }

    /// RLP packed transaction
    pub fn to_rlp(&self, chain_id: Option<u8>) -> Vec<u8> {
        let mut buf = Vec::new();
        self.to_rlp_raw(chain_id).write_rlp(&mut buf);

        buf
    }

    fn to_rlp_raw(&self, chain_id: Option<u8>) -> RLPList {
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

        if let Some(id) = chain_id {
            data.push(&id);
            data.push(&[][..]);
            data.push(&[][..]);
        }

        data
    }

    fn hash(&self, chain: u8) -> [u8; KECCAK256_BYTES] {
        let rlp = self.to_rlp_raw(Some(chain));
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
            to: Some("0x3f4E0668C20E100d7C2A27D4b177Ac65B2875D26"
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
           "to":"0x3f4E0668C20E100d7C2A27D4b177Ac65B2875D26",
           "value":"0x0de0b6b3a7640000",
           "data":"",
           "chainId":61
        }
        */

        let pk = PrivateKey(to_32bytes(
            "00b413b37c71bfb92719d16e28d7329dea5befa0d0b8190742f89e55617991cf",
        ));

        let hex = hex::encode(tx.to_signed_raw(pk, 61 /*MAINNET_ID*/).unwrap());
        assert_eq!(hex,
                    "f86d\
                    808504e3b29200825208\
                    94\
                    3f4e0668c20e100d7c2a27d4b177ac65b2875d26\
                    88\
                    0de0b6b3a7640000\
                    80\
                    81\
                    9e\
                    a0\
                    4ca75f697cf61daf1980dcd4f4460450e9e07b3c1b16ad1224b1a46e7e5c53b2\
                    a0\
                    59648e92e975d9cdf5d12698d7267595c087e83e9598639e13525f6fe7c047f1");
    }

    #[test]
    fn should_sign_transaction_for_testnet() {
        let tx = Transaction {
            nonce: 1048585,
            gas_price: /* 20000000000 */
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

        assert_eq!(hex::encode(tx.to_signed_raw(pk, 62 /*TESTNET_ID*/).unwrap()),
                    "f871\
                    83\
                    100009\
                    85\
                    04a817c800\
                    82\
                    5208\
                    94\
                    163b454d1ccdd0a12e88341b12afb2c98044c599\
                    89\
                    1e7751166579880000\
                    80819fa0cc6cd05d41bbbeb71913bf403a09db118f22e4ed7ebf707fcfb483dd1cded\
                    890a03c0a3985771bc0f10cf9fe85e3ea3c17132e3f09551eaedb8d2ae97cec3ad9f7");
    }

    #[test]
    fn should_sign_transaction_eip155() {
        let tx = Transaction {
            nonce: 9,
            gas_price: /* 20,000,000,000 */
            to_32bytes("00000000000000000000000000000\
                        000000000000000000000000004a817c800"),
            gas_limit: 21000,
            to: Some("0x3535353535353535353535353535353535353535"
                .parse::<Address>()
                .unwrap()),
            value: to_32bytes("000000000000000000000000000000\
                0000000000000000000de0b6b3a7640000"),
            data: Vec::new(),
        };

        let pk = PrivateKey(to_32bytes(
            "4646464646464646464646464646464646464646464646464646464646464646",
        ));

        assert_eq!(hex::encode(tx.to_signed_raw(pk, 1 /*ETH mainnet*/).unwrap()),
                    "f86c\
                    09\
                    85\
                    04a817c800\
                    82\
                    5208\
                    94\
                    3535353535353535353535353535353535353535\
                    88\
                    0de0b6b3a7640000\
                    8025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa\
                    636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");
    }
}
