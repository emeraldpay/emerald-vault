use uuid::Uuid;
use crate::{
    structs::{
        seed::SeedRef,
        types::HasUuid
    },
    Address,
    core::chains::Blockchain,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Wallet {
    pub id: Uuid,
    pub label: Option<String>,
    pub accounts: Vec<WalletAccount>
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WalletAccount {
    pub blockchain: Blockchain,
    pub address: Option<Address>,
    pub key: PKType
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PKType {
    PrivateKeyRef(Uuid),
    SeedHd(SeedRef)
}

impl HasUuid for Wallet {
    fn get_id(&self) -> Uuid {
        self.id
    }
}
