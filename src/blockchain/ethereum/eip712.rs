/*
Copyright 2022 EmeraldPay, Inc

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
use ethers_core::types::transaction::eip712::{Eip712, TypedData};
use crate::error::VaultError;
use crate::ethereum::signature::SignableHash;
use crate::KECCAK256_BYTES;
use crate::convert::error::ConversionError;

pub fn parse_eip712<S: AsRef<str>>(json: S) -> Result<TypedData, VaultError>{
    let typed_data: TypedData = serde_json::from_str(json.as_ref())
        .map_err(|_| VaultError::ConversionError(ConversionError::InvalidJson))?;

    Ok(typed_data)
}

impl SignableHash for TypedData {

    fn hash(&self) -> Result<[u8; KECCAK256_BYTES], VaultError> {
        self.encode_eip712()
            .map_err(|_| VaultError::InvalidDataError("EIP-712 Format".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use crate::ethereum::signature::{EthereumBasicSignature};
    use crate::{EthereumAddress, EthereumPrivateKey};
    use crate::ethereum::eip712::parse_eip712;

    #[test]
    fn sign_test_1() {
        // test vector from the spec. the PK is sha3('cow')
        let pk = EthereumPrivateKey::from_str("0xc85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4").unwrap();
        let json = r#"
            {
            "types": {
                "EIP712Domain": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "version",
                        "type": "string"
                    },
                    {
                        "name": "chainId",
                        "type": "uint256"
                    },
                    {
                        "name": "verifyingContract",
                        "type": "address"
                    }
                ],
                "Person": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "wallet",
                        "type": "address"
                    }
                ],
                "Mail": [
                    {
                        "name": "from",
                        "type": "Person"
                    },
                    {
                        "name": "to",
                        "type": "Person"
                    },
                    {
                        "name": "contents",
                        "type": "string"
                    }
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                },
                "contents": "Hello, Bob!"
            }
        }"#;

        let msg = parse_eip712(json);

        assert!(msg.is_ok());

        let msg = msg.unwrap();

        let signature = pk.sign::<EthereumBasicSignature>(&msg);
        assert!(signature.is_ok());

        assert_eq!(
            "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c".to_string(),
            signature.unwrap().to_string()
        )
    }

    #[test]
    fn verify_test_1() {
        // test vector from the spec. the PK is sha3('cow')
        let json = r#"
            {
            "types": {
                "EIP712Domain": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "version",
                        "type": "string"
                    },
                    {
                        "name": "chainId",
                        "type": "uint256"
                    },
                    {
                        "name": "verifyingContract",
                        "type": "address"
                    }
                ],
                "Person": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "wallet",
                        "type": "address"
                    }
                ],
                "Mail": [
                    {
                        "name": "from",
                        "type": "Person"
                    },
                    {
                        "name": "to",
                        "type": "Person"
                    },
                    {
                        "name": "contents",
                        "type": "string"
                    }
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                },
                "contents": "Hello, Bob!"
            }
        }"#;

        let msg = parse_eip712(json).unwrap();
        let exp_address = EthereumAddress::from_str("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826").unwrap();
        let signature = EthereumBasicSignature::from_str(
            "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c"
        ).unwrap();

        let verify = signature.verify(&msg, &exp_address);
        assert!(verify.is_ok());
        assert_eq!(verify.unwrap(), true);
    }
}
