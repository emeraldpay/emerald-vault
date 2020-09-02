use crate::convert::error::ConversionError;
use crate::{
    blockchain::chains::Blockchain,
    proto::{
        address::{Address as proto_Address, Address_oneof_address_type as proto_AddressType},
        book::BookItem as proto_BookItem,
        common::FileType as proto_FileType,
    },
    structs::book::{AddressRef, BookmarkDetails},
    util::optional::none_if_empty,
    EthereumAddress,
};
use protobuf::{parse_from_bytes, Message};
use std::convert::TryFrom;
use std::str::FromStr;
use chrono::{Utc, TimeZone};

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for BookmarkDetails {
    type Error = ConversionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let m = parse_from_bytes::<proto_BookItem>(value)?;

        let address = match &m.get_address().address_type {
            Some(t) => match t {
                proto_AddressType::plain_address(s) => EthereumAddress::from_str(s.as_str()),
                _ => {
                    return Err(ConversionError::InvalidFieldValue(
                        "address_type".to_string(),
                    ))
                }
            },
            None => {
                return Err(ConversionError::InvalidFieldValue(
                    "address is empty".to_string(),
                ))
            }
        }?;

        let blockchain = Blockchain::try_from(m.get_blockchain())
            .map_err(|_| ConversionError::InvalidFieldValue("blockchain".to_string()))?;
        let created_at = Utc.timestamp_millis_opt(m.get_created_at() as i64)
            .single().unwrap_or_else(|| Utc.timestamp_millis(0));
        let result = BookmarkDetails {
            blockchain,
            label: none_if_empty(m.get_label()),
            description: none_if_empty(m.get_description()),
            address: AddressRef::EthereumAddress(address),
            created_at,
        };

        Ok(result)
    }
}

/// Read from Protobuf bytes
impl TryFrom<Vec<u8>> for BookmarkDetails {
    type Error = ConversionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        BookmarkDetails::try_from(value.as_slice())
    }
}

/// Write as Protobuf bytes
impl TryFrom<BookmarkDetails> for Vec<u8> {
    type Error = ConversionError;

    fn try_from(value: BookmarkDetails) -> Result<Self, Self::Error> {
        let mut m = proto_BookItem::new();
        m.set_file_type(proto_FileType::FILE_BOOK);
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
        m.set_created_at(value.created_at.timestamp_millis() as u64);
        m.write_to_bytes().map_err(|e| ConversionError::from(e))
    }
}

#[cfg(test)]
mod tests {
    use crate::structs::book::{BookmarkDetails, AddressRef};
    use crate::chains::Blockchain;
    use crate::EthereumAddress;
    use std::str::FromStr;
    use chrono::{Utc, TimeZone};
    use protobuf::{parse_from_bytes, Message};
    use crate::proto::book::BookItem as proto_BootItem;
    use crate::proto::address::Address as proto_Address;
    use std::convert::{TryInto, TryFrom};

    #[test]
    fn write_as_protobuf() {
        let item = BookmarkDetails {
            blockchain: Blockchain::Ethereum,
            label: Some("Hello".to_string()),
            description: None,
            address: AddressRef::EthereumAddress(EthereumAddress::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap()),
            created_at: Utc.timestamp_millis(1592624592679),
        };

        let b: Vec<u8> = item.try_into().unwrap();
        assert!(b.len() > 0);
        let act = parse_from_bytes::<proto_BootItem>(b.as_slice()).unwrap();
        assert_eq!(act.label, "Hello".to_string());
        assert!(act.has_address());
        assert_eq!(act.get_address().get_plain_address(), "0x6412c428fc02902d137b60dc0bd0f6cd1255ea99");
        assert_eq!(act.created_at, 1592624592679);
    }

    #[test]
    fn write_and_read() {
        let item = BookmarkDetails {
            blockchain: Blockchain::EthereumClassic,
            label: Some("Hello".to_string()),
            description: Some("World!".to_string()),
            address: AddressRef::EthereumAddress(EthereumAddress::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap()),
            created_at: Utc.timestamp_millis(1592624592679),
        };

        let b: Vec<u8> = item.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = BookmarkDetails::try_from(b).unwrap();
        assert_eq!(act, item);
    }

    #[test]
    fn ignore_big_created_at() {
        let mut m = proto_BootItem::new();
        m.set_created_at((i64::MAX as u64) + 100);
        let mut ma = proto_Address::new();
        ma.set_plain_address("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99".to_string());
        m.set_address(ma);
        m.set_blockchain(100);

        let buf = m.write_to_bytes().unwrap();
        let act = BookmarkDetails::try_from(buf).unwrap();
        assert_eq!(act.created_at.timestamp_millis(), 0);
    }
}
