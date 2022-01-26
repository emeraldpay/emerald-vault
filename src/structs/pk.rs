use crate::{
    structs::{crypto::Encrypted, types::HasUuid},
    EthereumAddress,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::structs::types::UsesGlobalKey;

#[derive(PartialEq, Eq)]
pub struct PrivateKeyHolder {
    pub id: Uuid,
    pub pk: PrivateKeyType,
    ///creation date of the pk
    pub created_at: DateTime<Utc>,
}

#[derive(PartialEq, Eq)]
pub enum PrivateKeyType {
    EthereumPk(EthereumPk3),
}

#[derive(PartialEq, Eq)]
pub struct EthereumPk3 {
    pub address: Option<EthereumAddress>,
    pub key: Encrypted,
}

impl HasUuid for PrivateKeyHolder {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl PrivateKeyHolder {
    pub fn generate_id(&mut self) -> Uuid {
        self.id = Uuid::new_v4();
        self.id.clone()
    }
}

impl UsesGlobalKey for PrivateKeyHolder {
    fn is_using_global(&self) -> bool {
        match &self.pk {
            PrivateKeyType::EthereumPk(e) => e.key.is_using_global()
        }
    }
}

ord_by_date_id!(PrivateKeyHolder);
