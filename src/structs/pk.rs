use crate::{
    structs::{crypto::Encrypted, types::HasUuid},
    EthereumAddress,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::crypto::error::CryptoError;
use crate::structs::crypto::GlobalKey;
use crate::structs::types::UsesOddKey;

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKeyHolder {
    pub id: Uuid,
    pub pk: PrivateKeyType,
    ///creation date of the pk
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq)]
pub enum PrivateKeyType {
    EthereumPk(EthereumPk3),
}

#[derive(Clone, PartialEq, Eq)]
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

    pub(crate) fn reencrypt(self, password: &[u8], global_password: &[u8], global: GlobalKey) -> Result<Self, CryptoError> {
        let pk = match self.pk {
            PrivateKeyType::EthereumPk(e) => PrivateKeyType::EthereumPk(
                EthereumPk3 {
                    key: e.key.reencrypt(Some(password), global_password, global)?,
                    ..e
                }
            )
        };
        Ok(PrivateKeyHolder {
            pk,
            ..self
        })
    }
}

impl UsesOddKey for PrivateKeyHolder {
    fn is_odd_key(&self) -> bool {
        match &self.pk {
            PrivateKeyType::EthereumPk(e) => e.key.is_odd_key()
        }
    }
}

ord_by_date_id!(PrivateKeyHolder);
