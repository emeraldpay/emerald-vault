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
//! # Account transaction

use super::{super::error::Error, EthereumAddress, EthereumPrivateKey, EthereumSignature};
use crate::{
    blockchain::chains::EthereumChainId,
    util::{keccak256, trim_bytes, KECCAK256_BYTES},
};
use rlp::RlpStream;

/// Transaction data
#[derive(Clone, Debug, Default)]
pub struct EthereumTransaction {
    /// Nonce
    pub nonce: u64,

    /// Gas Price
    pub gas_price: [u8; 32], //TODO why 32??? why slice?

    /// Gas Limit
    pub gas_limit: u64,

    /// Target address, or None to create contract
    pub to: Option<EthereumAddress>,

    /// Value transferred with transaction
    pub value: [u8; 32], //TODO why 32??? why slice?

    /// Data transferred with transaction
    pub data: Vec<u8>,
}

impl EthereumTransaction {
    /// Sign transaction data with provided private key
    pub fn to_signed_raw(
        &self,
        pk: EthereumPrivateKey,
        chain: EthereumChainId,
    ) -> Result<Vec<u8>, Error> {
        let sig = pk.sign_hash(self.hash(chain.as_chainid()))?;
        Ok(self.raw_from_sig(Some(chain.as_chainid()), &sig))
    }

    /// RLP packed signed transaction from provided `Signature`
    /// chain MUST NOT be specified for transactions signed by Ledger
    pub fn raw_from_sig(&self, chain: Option<u8>, sig: &EthereumSignature) -> Vec<u8> {
        let mut rlp = self.to_rlp_raw(None);

        let mut v = u16::from(sig.v);
        match chain {
            Some(chain_id) => {
                // [Simple replay attack protection](https://github.com/ethereum/eips/issues/155)
                // Can be already applied by HD wallet.
                // TODO: refactor to avoid this check
                let stamp = u16::from(chain_id * 2 + 35 - 27);
                if v + stamp <= 0xff {
                    v += stamp;
                }
            }
            _ => {}
        }

        rlp.append(&(v as u8));
        rlp.append(&trim_bytes(&sig.r[..]));
        rlp.append(&trim_bytes(&sig.s[..]));

        rlp.finalize_unbounded_list();
        rlp.out().to_vec()
    }

    /// RLP packed transaction
    pub fn to_rlp(&self, chain_id: Option<u8>) -> Vec<u8> {
        // let mut buf = Vec::new();
        let mut rlp = self.to_rlp_raw(chain_id);
        rlp.finalize_unbounded_list();
        rlp.out().to_vec()
    }

    fn to_rlp_raw(&self, chain_id: Option<u8>) -> RlpStream {
        let mut data = RlpStream::new();
        data.begin_unbounded_list();

        data.append(&self.nonce);
        data.append(&trim_bytes(&self.gas_price));
        data.append(&self.gas_limit);

        match self.to {
            Some(addr) => data.append(&addr.0.as_ref()),
            _ => data.append_empty_data(),
        };

        data.append(&trim_bytes(&self.value));
        if self.data.is_empty() {
            data.append_empty_data();
        } else {
            data.append(&self.data);
        }

        if let Some(id) = chain_id {
            data.append(&id);
            data.append_empty_data();
            data.append_empty_data();
        }

        data
    }

    fn hash(&self, chain: u8) -> [u8; KECCAK256_BYTES] {
        let mut rlp = self.to_rlp_raw(Some(chain));
        rlp.finalize_unbounded_list();
        let vec = rlp.out();

        keccak256(&vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blockchain::ethereum::EthereumAddress, tests::*};

    #[test]
    fn encode_tx() {
        let tx = EthereumTransaction {
            nonce: 1,
            gas_price: to_32bytes(
                "00000000000000000000000000000000000000000000000000000004e3b29200",
            ),
            gas_limit: 21000,
            to: Some(
                "0x3eaf0b987b49c4d782ee134fdc1243fd0ccdfdd3"
                    .parse::<EthereumAddress>()
                    .unwrap(),
            ),
            value: to_32bytes("00000000000000000000000000000000000000000000000000DE0B6B3A764000"),
            data: Vec::new(),
        };
        let rlp = tx.to_rlp(Some(0x25));
        let hex = hex::encode(rlp);

        assert_eq!(
            hex,
            "".to_owned() +
                       "eb" + //total size = 1 +6 +3 +21 +8 +1 +1 +1 +1 + 0xc0
                       "01" + //nonce
                       "85" + "04e3b29200" + //gasprice
                       "82" + "5208" + //gas
                       "94" + "3eaf0b987b49c4d782ee134fdc1243fd0ccdfdd3" + // to
                       "87" + "de0b6b3a764000" + //value
                       "80" + //data
                       "25" + //v
                       "80" + //r
                       "80" //s
        );
    }

    #[test]
    fn encode_tx_with_small_gassprice() {
        let tx = EthereumTransaction {
            nonce: 0,
            gas_price: to_32bytes(
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            gas_limit: 21000,
            to: Some(
                "0x3eaf0b987b49c4d782ee134fdc1243fd0ccdfdd3"
                    .parse::<EthereumAddress>()
                    .unwrap(),
            ),
            value: to_32bytes("0000000000000000000000000000000000000000000000000000000000000000"),
            data: Vec::new(),
        };
        let rlp = tx.to_rlp(Some(0x25));
        let hex = hex::encode(rlp);

        assert_eq!(
            hex,
            "".to_owned() +
                    "df" + //total size = 1 +1 +3 +21 +1 +1 +1 +1 +1 + 0xc0
                    "80" + //nonce
                    "01" + //gasprice
                    "82" + "5208" + //gas
                    "94" + "3eaf0b987b49c4d782ee134fdc1243fd0ccdfdd3" + // to
                    "80" + //value
                    "80" + //data
                    "25" + //v
                    "80" + //r
                    "80" //s
        );
    }

    #[test]
    fn should_sign_transaction_for_mainnet() {
        let tx = EthereumTransaction {
            nonce: 0,
            gas_price: /* 21000000000 */
            to_32bytes("0000000000000000000000000000000\
                              0000000000000000000000004e3b29200"),
            gas_limit: 21000,
            to: Some("0x3f4E0668C20E100d7C2A27D4b177Ac65B2875D26"
                .parse::<EthereumAddress>()
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

        let pk = EthereumPrivateKey(to_32bytes(
            "00b413b37c71bfb92719d16e28d7329dea5befa0d0b8190742f89e55617991cf",
        ));

        let hex = hex::encode(
            tx.to_signed_raw(pk, EthereumChainId::EthereumClassic)
                .unwrap(),
        );
        assert_eq!(
            hex,
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
             59648e92e975d9cdf5d12698d7267595c087e83e9598639e13525f6fe7c047f1"
        );
    }

    #[test]
    fn should_sign_transaction_for_testnet() {
        let tx = EthereumTransaction {
            nonce: 1048585,
            gas_price: /* 20000000000 */
            to_32bytes("00000000000000000000000000000\
                        000000000000000000000000004a817c800"),
            gas_limit: 21000,
            to: Some("0x163b454d1ccdd0a12e88341b12afb2c98044c599"
                .parse::<EthereumAddress>()
                .unwrap()),
            value: /* 562 ETC */
            to_32bytes("000000000000000000000000000000\
                        00000000000000001e7751166579880000"),
            data: Vec::new(),
        };

        let pk = EthereumPrivateKey(to_32bytes(
            "28b469dc4b039ff63fcd4cb708c668545e644cb25f21df6920aac20e4bc743f7",
        ));

        assert_eq!(
            hex::encode(tx.to_signed_raw(pk, EthereumChainId::Kovan).unwrap()),
            // verified with MEW
            "f870\
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
             8078a0bc2a17e673bcd60b621f02a2c2d6546a9e1f0c1a67d0e0a0acfcd3fd171a38\
             30a0443b722a14da921f67a0b5aad9dd321483355b32d1fd3f01fb615be055416a58"
        );
    }

    #[test]
    fn should_sign_transaction_eip155() {
        let tx = EthereumTransaction {
            nonce: 9,
            gas_price: /* 20,000,000,000 */
            to_32bytes("00000000000000000000000000000\
                        000000000000000000000000004a817c800"),
            gas_limit: 21000,
            to: Some("0x3535353535353535353535353535353535353535"
                .parse::<EthereumAddress>()
                .unwrap()),
            value: to_32bytes("000000000000000000000000000000\
                0000000000000000000de0b6b3a7640000"),
            data: Vec::new(),
        };

        let pk = EthereumPrivateKey(to_32bytes(
            "4646464646464646464646464646464646464646464646464646464646464646",
        ));

        assert_eq!(
            hex::encode(tx.to_signed_raw(pk, EthereumChainId::Ethereum).unwrap()),
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
             636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
    }

    #[test]
    fn rs_should_be_quantity_1() {
        // ref https://github.com/ethereum/web3.js/issues/1170
        let tx = EthereumTransaction {
            nonce: 0,
            gas_price: /* 234,567,897,654,321 */
            to_32bytes("0000000000000000000000000000000000000000000000000000D55698372431"),
            gas_limit: 2000000,
            to: Some("0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"
                .parse::<EthereumAddress>()
                .unwrap()),
            value:
            to_32bytes("000000000000000000000000000000000000000000000000000000003B9ACA00"),
            data: Vec::new(),
        };

        let pk = EthereumPrivateKey(to_32bytes(
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
        ));

        let hex = hex::encode(tx.to_signed_raw(pk, EthereumChainId::Ethereum).unwrap());
        assert_eq!(hex,
                   "f86a8086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca008025a00\
                   9ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9c\
                   a0\
                   440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428");
    }

    #[test]
    fn rs_should_be_quantity_2() {
        // ref https://github.com/ethereum/web3.js/issues/1170
        let tx = EthereumTransaction {
            nonce: 0,
            gas_price: /* 234,567,897,654,321 */
            to_32bytes("0000000000000000000000000000000000000000000000000000000000000000"),
            gas_limit: 31853,
            to: Some("0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"
                .parse::<EthereumAddress>()
                .unwrap()),
            value:
            to_32bytes("0000000000000000000000000000000000000000000000000000000000000000"),
            data: Vec::new(),
        };

        let pk = EthereumPrivateKey(to_32bytes(
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
        ));

        let hex = hex::encode(tx.to_signed_raw(pk, EthereumChainId::Ethereum).unwrap());
        assert_eq!(
            hex,
            "f85d8080827c6d94f0109fc8df283027b6285cc889f5aa624eac1f558080269f\
             22f17b38af35286ffbb0c6376c86ec91c20ecbad93f84913a0cc15e7580cd9\
             9f\
             83d6e12e82e3544cb4439964d5087da78f74cefeec9a450b16ae179fd8fe20"
        );
    }
}
