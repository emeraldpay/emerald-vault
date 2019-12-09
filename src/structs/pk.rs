use uuid::Uuid;
use crate::Address;
use crate::structs::crypto::Encrypted;
use crate::structs::types::HasUuid;

pub struct PrivateKeyHolder {
    pub id: Uuid,
    pub pk: PrivateKeyType
}

pub enum PrivateKeyType {
    EthereumPk(EthereumPk3)
}

pub struct EthereumPk3 {
    pub address: Option<Address>,
    pub key: Encrypted
}

impl HasUuid for PrivateKeyHolder {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl PrivateKeyHolder {
    pub fn generate_id(&mut self) {
        self.id = Uuid::new_v4();
    }
}
