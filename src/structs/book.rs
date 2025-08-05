use crate::{
    blockchain::{bitcoin::XPub, chains::Blockchain},
    EthereumAddress,
};
use chrono::{DateTime, Utc};
use bitcoin::Address as BitcoinAddress;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BookmarkDetails {
    pub blockchain: Blockchain,
    pub label: Option<String>,
    pub description: Option<String>,
    pub address: AddressRef,
    ///creation date of the item
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub enum AddressRef {
    EthereumAddress(EthereumAddress),
    ExtendedPub(XPub),
    BitcoinAddress(BitcoinAddress)
}

impl std::fmt::Display for AddressRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressRef::EthereumAddress(v) => write!(f, "{}", v),
            AddressRef::BitcoinAddress(v) => write!(f, "{}", v),
            AddressRef::ExtendedPub(v) => write!(f, "{}", v)
        }
    }
}
