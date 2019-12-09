use crate::Address;
use crate::core::chains::Blockchain;

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
