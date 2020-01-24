use crate::core::chains::Blockchain;
use crate::Address;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BookmarkDetails {
    pub blockchain: Blockchain,
    pub label: Option<String>,
    pub description: Option<String>,
    pub address: AddressRef,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AddressRef {
    EthereumAddress(Address),
}
