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

use num_bigint::BigUint;
use super::{EthereumAddress, EthereumPrivateKey, EthereumSignature};
use crate::{
    blockchain::chains::EthereumChainId,
    util::{keccak256, trim_bytes, KECCAK256_BYTES},
};
use rlp::RlpStream;
use crate::error::VaultError;
use crate::ethereum::signature::{EthereumBasicSignature, EthereumEIP2930Signature};

/// Transaction data
#[derive(Clone, Debug)]
pub struct EthereumLegacyTransaction {
    /// Chain ID
    pub chain_id: EthereumChainId,
    /// Nonce
    pub nonce: u64,
    /// Gas Price
    pub gas_price: BigUint,
    /// Gas Limit
    pub gas_limit: u64,
    /// Target address, or None to create contract
    pub to: Option<EthereumAddress>,
    /// Value transferred with transaction
    pub value: BigUint,
    /// Data transferred with transaction
    pub data: Vec<u8>,
}

///
/// Transaction Access List as defined by EIP-2930
pub struct TxAccess {
    pub address: EthereumAddress,
    pub storage_keys: Vec<[u8; 32]>,
}

///
/// Transaction with Gas Priority, as defined by EIP-1559
pub struct EthereumEIP1559Transaction {
    /// Chain ID
    pub chain_id: EthereumChainId,
    /// Nonce
    pub nonce: u64,
    /// Max Gas Price
    pub max_gas_price: BigUint,
    /// Max Gas Price
    pub priority_gas_price: BigUint,
    /// Gas Limit
    pub gas_limit: u64,
    /// Target address, or None to create a contract
    pub to: Option<EthereumAddress>,
    /// Value transferred with transaction
    pub value: BigUint,
    /// Data transferred with transaction
    pub data: Vec<u8>,
    /// List of contracts the transaction is expected to access. Can be empty
    pub access: Vec<TxAccess>,
}

pub trait EthereumTransaction {

    ///
    /// Sign transaction with the provided Private Key and encode it as RLP. Result is ready to
    /// use transaction, can be executed, broadcast, etc.
    fn sign(
        &self,
        pk: EthereumPrivateKey
    ) -> Result<Vec<u8>, VaultError>;

    ///
    /// Encode the transaction to the provided RPL Stream
    ///
    /// - `empty_sig` is a flag for default Ethereum Tx that specifies if RPL should include _signature placeholder values_,
    /// i.e., when it should put an empty signature. For modern EIP-2930 signature the flag is not used
    fn encode_into(&self, rlp: &mut RlpStream, empty_sig: bool);

    ///
    /// Chain Id, if specified. `None` is possible only for legacy transactions without EIP-155
    fn get_chain(&self) -> EthereumChainId;

    ///
    /// RLP encoded transaction without signature
    fn encode_unsigned(&self) -> Vec<u8> {
        let mut rlp = RlpStream::new();
        self.encode_into(&mut rlp, true);
        rlp.finalize_unbounded_list();
        rlp.out().to_vec()
    }

    ///
    /// RLP encode transaction with provided `Signature`
    /// chain MUST NOT be specified for transactions signed by Ledger
    fn encode_signed(&self, sig: &dyn EthereumSignature) -> Vec<u8> {
        let mut rlp = RlpStream::new();
        self.encode_into(&mut rlp, false);

        sig.append_to_rlp(self.get_chain(), &mut rlp);

        rlp.finalize_unbounded_list();
        rlp.out().to_vec()
    }


    ///
    /// Hash of the transaction. Used as TX ID and to make a signature
    fn hash(&self) -> [u8; KECCAK256_BYTES] {
        let mut rlp = RlpStream::new();
        self.encode_into(&mut rlp, true);
        rlp.finalize_unbounded_list();
        let vec = rlp.out();

        keccak256(&vec)
    }
}

impl EthereumTransaction for EthereumLegacyTransaction {
    /// Sign transaction data with provided private key
    fn sign(
        &self,
        pk: EthereumPrivateKey
    ) -> Result<Vec<u8>, VaultError> {
        let sig = pk.sign_hash::<EthereumBasicSignature>(self.hash())?;
        Ok(self.encode_signed(&sig))
    }

    fn encode_into(&self, rlp: &mut RlpStream, empty_sig: bool) {
        rlp.begin_unbounded_list();

        rlp.append(&self.nonce);
        rlp.append(&trim_bytes(&self.gas_price.to_bytes_be()));
        rlp.append(&self.gas_limit);

        match self.to {
            Some(addr) => rlp.append(&addr.0.as_ref()),
            _ => rlp.append_empty_data(),
        };

        rlp.append(&trim_bytes(&self.value.to_bytes_be()));
        if self.data.is_empty() {
            rlp.append_empty_data();
        } else {
            rlp.append(&self.data);
        }

        // put no-signature values to show it's an unsigned transaction. for a signed transaction there goes a signature values
        if empty_sig {
            rlp.append(&self.chain_id.as_chainid());
            rlp.append_empty_data();
            rlp.append_empty_data();
        }
    }

    fn get_chain(&self) -> EthereumChainId {
        self.chain_id
    }

}

impl EthereumTransaction for EthereumEIP1559Transaction {
    fn sign(&self, pk: EthereumPrivateKey) -> Result<Vec<u8>, VaultError> {
        let sig = pk.sign_hash::<EthereumEIP2930Signature>(self.hash())?;
        Ok(self.encode_signed(&sig))
    }

    fn encode_into(&self, rlp: &mut RlpStream, _empty_sig: bool) {
        // first byte is a type of the transaction, as per EIP-2718. Where 2 is for EIP-1559 transaction
        rlp.append_raw(&[2], 1);
        rlp.begin_unbounded_list();
        rlp.append(&self.chain_id.as_chainid());
        rlp.append(&self.nonce);
        rlp.append(&trim_bytes(&self.priority_gas_price.to_bytes_be()));
        rlp.append(&trim_bytes(&self.max_gas_price.to_bytes_be()));
        rlp.append(&self.gas_limit);
        match self.to {
            Some(addr) => rlp.append(&addr.0.as_ref()),
            _ => rlp.append_empty_data(),
        };
        rlp.append(&trim_bytes(&self.value.to_bytes_be()));
        if self.data.is_empty() {
            rlp.append_empty_data();
        } else {
            rlp.append(&self.data);
        }

        rlp.begin_unbounded_list();
        for access in &self.access {
            rlp.begin_unbounded_list();
            rlp.append(&access.address.0.as_ref());
            rlp.begin_list(access.storage_keys.len());
            for storage in &access.storage_keys {
                rlp.append_raw(storage, 32);
            }
            rlp.finalize_unbounded_list();
        }
        rlp.finalize_unbounded_list();
    }

    fn get_chain(&self) -> EthereumChainId {
        return self.chain_id
    }

}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use num::{Num, Zero};
    use super::*;
    use crate::{blockchain::ethereum::EthereumAddress, tests::*};

    #[test]
    fn encode_tx() {
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Custom(0x25),
            nonce: 1,
            gas_price: BigUint::from_str_radix(
                "00000000000000000000000000000000000000000000000000000004e3b29200", 16
            ).unwrap(),
            gas_limit: 21000,
            to: Some(
                "0x3eaf0b987b49c4d782ee134fdc1243fd0ccdfdd3"
                    .parse::<EthereumAddress>()
                    .unwrap(),
            ),
            value: BigUint::from_str_radix("00000000000000000000000000000000000000000000000000DE0B6B3A764000", 16).unwrap(),
            data: Vec::new(),
        };
        let rlp = tx.encode_unsigned();
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
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Custom(0x25),
            nonce: 0,
            gas_price: BigUint::from(1u32),
            gas_limit: 21000,
            to: Some(
                "0x3eaf0b987b49c4d782ee134fdc1243fd0ccdfdd3"
                    .parse::<EthereumAddress>()
                    .unwrap(),
            ),
            value: BigUint::zero(),
            data: Vec::new(),
        };
        let rlp = tx.encode_unsigned();
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
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::EthereumClassic,
            nonce: 0,
            gas_price: /* 21000000000 */
            BigUint::from_str_radix("04e3b29200", 16).unwrap(),
            gas_limit: 21000,
            to: Some("0x3f4E0668C20E100d7C2A27D4b177Ac65B2875D26"
                .parse::<EthereumAddress>()
                .unwrap()),
            value: /* 1 ETC */
            BigUint::from_str_radix("0de0b6b3a7640000", 16).unwrap(),
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
            tx.sign(pk)
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
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Kovan,
            nonce: 1048585,
            gas_price: /* 20000000000 */
            BigUint::from_str_radix("00000000000000000000000000000\
                        000000000000000000000000004a817c800", 16).unwrap(),
            gas_limit: 21000,
            to: Some("0x163b454d1ccdd0a12e88341b12afb2c98044c599"
                .parse::<EthereumAddress>()
                .unwrap()),
            value: /* 562 ETC */
            BigUint::from_str_radix("000000000000000000000000000000\
                        00000000000000001e7751166579880000", 16).unwrap(),
            data: Vec::new(),
        };

        let pk = EthereumPrivateKey(to_32bytes(
            "28b469dc4b039ff63fcd4cb708c668545e644cb25f21df6920aac20e4bc743f7",
        ));

        assert_eq!(
            hex::encode(tx.sign(pk).unwrap()),
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
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 9,
            gas_price: /* 20,000,000,000 */
            BigUint::from_str_radix("00000000000000000000000000000\
                        000000000000000000000000004a817c800", 16).unwrap(),
            gas_limit: 21000,
            to: Some("0x3535353535353535353535353535353535353535"
                .parse::<EthereumAddress>()
                .unwrap()),
            value: BigUint::from_str_radix("000000000000000000000000000000\
                0000000000000000000de0b6b3a7640000", 16).unwrap(),
            data: Vec::new(),
        };

        let pk = EthereumPrivateKey(to_32bytes(
            "4646464646464646464646464646464646464646464646464646464646464646",
        ));

        assert_eq!(
            hex::encode(tx.sign(pk).unwrap()),
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
    fn encode_tx_eip1559() {
        let tx = EthereumEIP1559Transaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 150,
            max_gas_price: BigUint::from_str("82684598939").unwrap(),
            priority_gas_price: BigUint::from_str("4000000000").unwrap(),
            gas_limit: 51101,
            to: Some("0x7bebd226154e865954a87650faefa8f485d36081"
                .parse::<EthereumAddress>()
                .unwrap()),
            value: BigUint::zero(),
            data: hex::decode("095ea7b300000000000000000000000003f7724180aa6b939894b5ca4314783b0b36b329ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap(),
            access: vec![]
        };

        let sig = EthereumEIP2930Signature {
            y_parity: 1,
            r: to_32bytes("d978ed98e78dd480b2aec86d1521962a8fe4009e44fb19f45b70d8005e602182"),
            s: to_32bytes("347c933f78131995c1abd07c1d0be67d8f04c2cf99cd79510657e97ead8c1a9f")
        };

        let encoded = tx.encode_signed(&sig);

        assert_eq!(
            hex::encode(encoded),
            "02f8b101819684ee6b280085134062da9b82c79d947bebd226154e865954a87650faefa8f485d3608180b844095ea7b300000000000000000000000003f7724180aa6b939894b5ca4314783b0b36b329ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc001a0d978ed98e78dd480b2aec86d1521962a8fe4009e44fb19f45b70d8005e602182a0347c933f78131995c1abd07c1d0be67d8f04c2cf99cd79510657e97ead8c1a9f"
        );
    }

    #[test]
    fn rs_should_be_quantity_1() {
        // ref https://github.com/ethereum/web3.js/issues/1170
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 0,
            gas_price: /* 234,567,897,654,321 */
            BigUint::from_str_radix("0000000000000000000000000000000000000000000000000000D55698372431", 16).unwrap(),
            gas_limit: 2000000,
            to: Some("0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"
                .parse::<EthereumAddress>()
                .unwrap()),
            value:
            BigUint::from_str_radix("000000000000000000000000000000000000000000000000000000003B9ACA00", 16).unwrap(),
            data: Vec::new(),
        };

        let pk = EthereumPrivateKey(to_32bytes(
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
        ));

        let hex = hex::encode(tx.sign(pk).unwrap());
        assert_eq!(hex,
                   "f86a8086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca008025a00\
                   9ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9c\
                   a0\
                   440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428");
    }

    #[test]
    fn rs_should_be_quantity_2() {
        // ref https://github.com/ethereum/web3.js/issues/1170
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 0,
            gas_price: /* 234,567,897,654,321 */
            BigUint::from_str_radix("0000000000000000000000000000000000000000000000000000000000000000", 16).unwrap(),
            gas_limit: 31853,
            to: Some("0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"
                .parse::<EthereumAddress>()
                .unwrap()),
            value:
            BigUint::from_str_radix("0000000000000000000000000000000000000000000000000000000000000000", 16).unwrap(),
            data: Vec::new(),
        };

        let pk = EthereumPrivateKey(to_32bytes(
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
        ));

        let hex = hex::encode(tx.sign(pk).unwrap());
        assert_eq!(
            hex,
            "f85d8080827c6d94f0109fc8df283027b6285cc889f5aa624eac1f558080269f\
             22f17b38af35286ffbb0c6376c86ec91c20ecbad93f84913a0cc15e7580cd9\
             9f\
             83d6e12e82e3544cb4439964d5087da78f74cefeec9a450b16ae179fd8fe20"
        );
    }

    #[test]
    fn create_tx_eip1559() {
        let tx = EthereumEIP1559Transaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 1234,
            max_gas_price: BigUint::from_str("20000000000").unwrap(), // 20 gwei
            priority_gas_price: BigUint::from_str("1000000000").unwrap(), // 1 gwei,
            gas_limit: 150_000,
            to: Some("0x3535353535353535353535353535353535353535"
                .parse::<EthereumAddress>()
                .unwrap()),
            value: BigUint::from_str("1234500000000000000").unwrap(), // 1.2345 ether
            data: Vec::new(),
            access: vec![]
        };

        let hash = hex::encode(tx.hash());
        assert_eq!(hash, "68fe011ba5be4a03369d51810e7943abab15fbaf757f9296711558aee8ab772b");

        let pk = EthereumPrivateKey(to_32bytes(
            "4646464646464646464646464646464646464646464646464646464646464646",
        ));

        let hex = hex::encode(tx.sign(pk).unwrap());
        assert_eq!(
            hex,
            "02f876018204d2843b9aca008504a817c800830249f0943535353535353535353535353535353535353535881121d3359738400080c001a0f0b3347ec48e78bf5ef6075b332334518ebc2f90d2bf0fea080623179936382ea05c58c5beeafb2398d5e79b40b320421112a9672167f27e7fc55e76d2d7d11062"
        );
    }
}
