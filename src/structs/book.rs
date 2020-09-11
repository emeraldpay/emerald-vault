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

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AddressRef {
    EthereumAddress(EthereumAddress),
    ExtendedPub(XPub),
    BitcoinAddress(BitcoinAddress)
}
