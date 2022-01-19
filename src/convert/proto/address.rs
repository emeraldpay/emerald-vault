use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};

use bitcoin::{
    util::bip32::{ChainCode, ChildNumber, ExtendedPubKey, Fingerprint},
    Network,
    PublicKey,
};
use protobuf::ProtobufEnum;

use crate::{
    blockchain::bitcoin::{AddressType, XPub},
    convert::error::ConversionError,
    proto::common::BlockchainId as proto_BlockchainId,
    proto::address::{
        Address as proto_Address,
        AddressType as proto_AddressType,
        Address_oneof_address_type as proto_AddressRefType,
        Bip32Public as proto_Bip32Public,
    },
    structs::book::AddressRef,
    EthereumAddress,
};
use crate::blockchain::chains::Blockchain;

impl From<AddressType> for proto_AddressType {
    fn from(value: AddressType) -> Self {
        match value {
            AddressType::P2PKH => proto_AddressType::BITCOIN_P2PKH,
            AddressType::P2SH => proto_AddressType::BITCOIN_P2SH,
            AddressType::P2WPKHinP2SH => proto_AddressType::BITCOIN_P2WPKH_P2SH,
            AddressType::P2WSHinP2SH => proto_AddressType::BITCOIN_P2WSH_P2SH,
            AddressType::P2WPKH => proto_AddressType::BITCOIN_P2WPKH,
            AddressType::P2WSH => proto_AddressType::BITCOIN_P2WSH,
        }
    }
}

impl From<&XPub> for proto_Bip32Public {
    fn from(xpub: &XPub) -> Self {
        let mut result = proto_Bip32Public::default();
        result.set_level(xpub.value.depth as u32);
        result.set_parent_fingerprint(u32::from_be_bytes(
            xpub.value.parent_fingerprint.as_bytes().clone(),
        ));
        result.set_child_number(xpub.value.child_number.into());
        result.set_chaincode(xpub.value.chain_code.as_bytes().to_vec());
        result.set_point(xpub.value.public_key.to_bytes());
        result.set_address_type(xpub.address_type.into());
        result.set_network(match xpub.value.network {
            Network::Bitcoin => proto_BlockchainId::CHAIN_BITCOIN,
            Network::Testnet | Network::Regtest | Network::Signet => proto_BlockchainId::CHAIN_TESTNET_BITCOIN,
        });
        result
    }
}

impl From<&AddressRef> for proto_Address {
    fn from(value: &AddressRef) -> Self {
        let mut result = proto_Address::default();
        match value {
            AddressRef::EthereumAddress(address) => {
                result.set_plain_address(address.to_string());
            }
            AddressRef::ExtendedPub(xpub) => result.set_xpub(xpub.into()),
            AddressRef::BitcoinAddress(address) => {
                result.set_plain_address(address.to_string())
            }
        }
        result
    }
}

impl TryFrom<proto_AddressType> for AddressType {
    type Error = ConversionError;

    fn try_from(value: proto_AddressType) -> Result<Self, Self::Error> {
        match value {
            proto_AddressType::BITCOIN_P2WPKH => Ok(AddressType::P2WPKH),
            proto_AddressType::BITCOIN_P2WSH => Ok(AddressType::P2WSH),
            proto_AddressType::BITCOIN_P2PKH => Ok(AddressType::P2PKH),
            proto_AddressType::BITCOIN_P2SH => Ok(AddressType::P2SH),
            proto_AddressType::BITCOIN_P2WPKH_P2SH => Ok(AddressType::P2WPKHinP2SH),
            proto_AddressType::BITCOIN_P2WSH_P2SH => Ok(AddressType::P2WSHinP2SH),
            _ => Err(ConversionError::InvalidFieldValue(
                value.value().to_string(),
            )),
        }
    }
}


impl TryFrom<&proto_Bip32Public> for XPub {
    type Error = ConversionError;

    fn try_from(value: &proto_Bip32Public) -> Result<Self, Self::Error> {
        let depth: u8 = if value.level <= 255 {
            value.level as u8
        } else {
            return Err(ConversionError::InvalidFieldValue("level".to_string()));
        };
        let parent_fingerprint = Fingerprint::from(value.parent_fingerprint.to_be_bytes().as_ref());
        let child_number = ChildNumber::from(value.child_number);
        let chain_code = if value.chaincode.len() == 32 {
            ChainCode::from(value.chaincode.as_slice())
        } else {
            return Err(ConversionError::InvalidFieldValue("chain_code".to_string()));
        };
        let public_key = PublicKey::from_slice(value.point.as_slice())
            .map_err(|_| ConversionError::InvalidFieldValue("public_key".to_string()))?;
        let address_type = value.address_type.try_into()?;
        let network = Blockchain::try_from(value.network.value() as u32)
            .map_err(|_| ConversionError::InvalidFieldValue("network".to_string()))?
            .as_bitcoin_network();

        Ok(XPub {
            address_type,
            value: ExtendedPubKey {
                network,
                depth,
                parent_fingerprint,
                child_number,
                public_key,
                chain_code,
            },
        })
    }
}

impl TryFrom<&proto_Address> for Option<AddressRef> {
    type Error = ConversionError;

    fn try_from(value: &proto_Address) -> Result<Self, Self::Error> {
        let result = match &value.address_type {
            Some(address_type) => match address_type {
                proto_AddressRefType::plain_address(a) => Some(AddressRef::EthereumAddress(
                    EthereumAddress::from_str(a.as_str())?,
                )),
                proto_AddressRefType::xpub(xpub) => {
                    Some(AddressRef::ExtendedPub(XPub::try_from(xpub)?))
                }
            },
            None => None,
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::TryInto, str::FromStr};

    use crate::{
        blockchain::bitcoin::XPub,
        proto::address::Address as proto_Address,
        structs::book::AddressRef,
        EthereumAddress,
    };

    #[test]
    fn encode_decode_plain_ethereum() {
        let initial = AddressRef::EthereumAddress(
            EthereumAddress::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7").unwrap(),
        );
        let m: proto_Address = (&initial).into();
        let act: Option<AddressRef> = (&m).try_into().expect("parsed back");
        assert_eq!(act, Some(initial));
    }

    #[test]
    fn encode_decode_xpub() {
        let initial = AddressRef::ExtendedPub(
            XPub::from_str("zpub6tMBbzkLBxnSw8VSGXrnyBSY3r2j4KJRrxrMWm1pskuhbCnKS8R5SuHGjakEvf6efbqsM1NoPMxXZrPmQWTV7ZXZuK9dZcbEzkftLBDJHKj").unwrap()
        );
        let m: proto_Address = (&initial).into();
        let act: Option<AddressRef> = (&m).try_into().expect("parsed back");
        assert_eq!(act, Some(initial));
    }

    #[test]
    fn encode_decode_testnet_xpub() {
        let initial = AddressRef::ExtendedPub(
            XPub::from_str("vpub5Yxb4hoHAGV32y67pPDQCbPFUbB9w95gkR1nCxv92t2axDYWeNV4xzo1wxgz8A1S5QGWusHzCP969uaBbt4hjV8CT3PKe7tfic4v9RMbFc4").unwrap()
        );
        let m: proto_Address = (&initial).into();
        let act: Option<AddressRef> = (&m).try_into().expect("parsed back");
        assert!(act.is_some());
        assert_eq!(act, Some(initial));
    }
}
