use crate::{
    core::chains::Blockchain,
    proto::{
        address::{Address as proto_Address, Address_oneof_address_type as proto_AddressType},
        book::BookItem as proto_BookItem,
    },
    storage::error::VaultError,
    structs::book::{AddressRef, BookmarkDetails},
    util::optional::none_if_empty,
    Address,
};
use protobuf::{parse_from_bytes, Message};
use std::convert::TryFrom;
use std::str::FromStr;

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for BookmarkDetails {
    type Error = VaultError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let m = parse_from_bytes::<proto_BookItem>(value)?;

        let address = match &m.get_address().address_type {
            Some(t) => match t {
                proto_AddressType::plain_address(s) => Address::from_str(s.as_str()),
                _ => return Err(VaultError::InvalidDataError("address_type".to_string())),
            },
            None => return Err(VaultError::InvalidDataError("address is empty".to_string())),
        }?;

        let blockchain = Blockchain::try_from(m.get_blockchain())?;

        let result = BookmarkDetails {
            blockchain,
            label: none_if_empty(m.get_label()),
            description: none_if_empty(m.get_description()),
            address: AddressRef::EthereumAddress(address),
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
        m.set_blockchain(value.blockchain as u32);
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

        m.write_to_bytes().map_err(|e| VaultError::from(e))
    }
}
