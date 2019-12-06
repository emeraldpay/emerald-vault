use crate::core::chains::Blockchain;
use crate::Address;
use uuid::Uuid;
use std::convert::TryFrom;
use crate::storage::error::VaultError;
use emerald_vault_proto::{
    book::{
        BookItem as proto_BookItem
    },
    address::{
        Address as proto_Address,
        Address_oneof_address_type as proto_AddressType
    }
};
use protobuf::{parse_from_bytes, Message};
use crate::util::optional::none_if_empty;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BookmarkDetails {
    pub blockchains: Vec<Blockchain>,
    pub label: Option<String>,
    pub description: Option<String>,
    pub address: AddressRef
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AddressRef {
    EthereumAddress(Address)
}

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for BookmarkDetails {
    type Error = VaultError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let m = parse_from_bytes::<proto_BookItem>(value)?;

        let address = match &m.get_address().address_type {
            Some(t) => {
                match t {
                    proto_AddressType::plain_address(s) => Address::from_str(s.as_str()),
                    _ => return Err(VaultError::InvalidDataError("address_type".to_string()))
                }
            },
            None => return Err(VaultError::InvalidDataError("address is empty".to_string()))
        }?;

        let blockchains = m.blockchains.iter()
            .map(|i| Blockchain::try_from(*i))
            .filter(|b| b.is_ok())
            .map(|b| b.unwrap())
            .collect();

        let result = BookmarkDetails {
            blockchains,
            label: none_if_empty(m.get_label()),
            description: none_if_empty(m.get_description()),
            address: AddressRef::EthereumAddress(address)
        };

        Ok(result)
    }
}

/// Read from Protobuf bytes
impl TryFrom<Vec<u8>> for BookmarkDetails {
    type Error = VaultError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        BookmarkDetails::try_from(value.as_slice())
    }
}

/// Write as Protobuf bytes
impl TryFrom<BookmarkDetails> for Vec<u8> {
    type Error = VaultError;

    fn try_from(value: BookmarkDetails) -> Result<Self, Self::Error> {
        let mut m = proto_BookItem::new();
        let blockchains = value.blockchains.iter()
            .map(|b| *b as u32)
            .collect();
        m.set_blockchains(blockchains);
        if value.label.is_some() {
            m.set_label(value.label.unwrap());
        }
        if value.description.is_some() {
            m.set_description(value.description.unwrap());
        }
        match value.address {
            AddressRef::EthereumAddress(address) => {
                let mut value = proto_Address::new();
                value.set_plain_address(address.to_string());
                m.set_address(value)
            }
        };

        m.write_to_bytes()
            .map_err(|e| VaultError::from(e))
    }
}
