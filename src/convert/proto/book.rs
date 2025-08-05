use crate::{
    blockchain::chains::Blockchain,
    convert::error::ConversionError,
    proto::{
        book::BookItem as proto_BookItem,
        common::FileType as proto_FileType,
    },
    structs::book::{BookmarkDetails},
    util::none_if_empty,
};
use chrono::{TimeZone, Utc};
use protobuf::Message;
use std::{convert::TryFrom};
use std::convert::TryInto;

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for BookmarkDetails {
    type Error = ConversionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let m = proto_BookItem::parse_from_bytes(value)?;
        let address = match &m.address.clone().into_option() {
            Some(address) => address.try_into()?,
            None => None,
        };

        if address.is_none() {
            return Err(ConversionError::InvalidFieldValue(
                "address is empty".to_string(),
            ))
        }

        let blockchain = Blockchain::try_from(m.get_blockchain())
            .map_err(|_| ConversionError::InvalidFieldValue("blockchain".to_string()))?;
        let created_at = Utc
            .timestamp_millis_opt(m.get_created_at() as i64)
            .single()
            .unwrap_or_else(|| Utc.timestamp_millis_opt(0).unwrap());
        let result = BookmarkDetails {
            blockchain,
            label: none_if_empty(m.get_label()),
            description: none_if_empty(m.get_description()),
            address: address.unwrap(),
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
        m.set_address((&value.address).into());
        m.set_created_at(value.created_at.timestamp_millis() as u64);
        m.write_to_bytes().map_err(ConversionError::from)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        chains::Blockchain,
        proto::{address::Address as proto_Address, book::BookItem as proto_BootItem},
        structs::book::{AddressRef, BookmarkDetails},
        EthereumAddress,
    };
    use chrono::{TimeZone, Utc};
    use protobuf::Message;
    use std::{
        convert::{TryFrom, TryInto},
        str::FromStr,
    };
    use crate::blockchain::bitcoin::XPub;

    #[test]
    fn write_as_protobuf() {
        let item = BookmarkDetails {
            blockchain: Blockchain::Ethereum,
            label: Some("Hello".to_string()),
            description: None,
            address: AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap(),
            ),
            created_at: Utc.timestamp_millis_opt(1592624592679).unwrap(),
        };

        let b: Vec<u8> = item.try_into().unwrap();
        assert!(!b.is_empty());
        let act = proto_BootItem::parse_from_bytes(b.as_slice()).unwrap();
        assert_eq!(act.label, "Hello".to_string());
        assert!(act.has_address());
        assert_eq!(
            act.get_address().get_plain_address(),
            "0x6412c428fc02902d137b60dc0bd0f6cd1255ea99"
        );
        assert_eq!(act.created_at, 1592624592679);
    }

    #[test]
    fn write_and_read() {
        let item = BookmarkDetails {
            blockchain: Blockchain::EthereumClassic,
            label: Some("Hello".to_string()),
            description: Some("World!".to_string()),
            address: AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap(),
            ),
            created_at: Utc.timestamp_millis_opt(1592624592679).unwrap(),
        };

        let b: Vec<u8> = item.clone().try_into().unwrap();
        assert!(!b.is_empty());
        let act = BookmarkDetails::try_from(b).unwrap();
        assert_eq!(act, item);
    }

    #[test]
    fn write_and_read_xpub() {
        let item = BookmarkDetails {
            blockchain: Blockchain::Bitcoin,
            label: Some("Hello".to_string()),
            description: Some("World!".to_string()),
            address: AddressRef::ExtendedPub(
                XPub::from_str("zpub6tMBbzkLBxnSw8VSGXrnyBSY3r2j4KJRrxrMWm1pskuhbCnKS8R5SuHGjakEvf6efbqsM1NoPMxXZrPmQWTV7ZXZuK9dZcbEzkftLBDJHKj").unwrap(),
            ),
            created_at: Utc.timestamp_millis_opt(1592624592679).unwrap(),
        };

        let b: Vec<u8> = item.clone().try_into().unwrap();
        assert!(!b.is_empty());
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
