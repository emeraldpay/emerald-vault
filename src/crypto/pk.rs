use crate::{
    blockchain::{EthereumAddress, EthereumPrivateKey as core_PK},
    crypto::error::CryptoError,
    structs::{
        crypto::Encrypted,
        pk::{EthereumPk3, PrivateKeyHolder, PrivateKeyType},
    },
};
use chrono::Utc;
use std::convert::TryFrom;
use uuid::Uuid;
use crate::structs::crypto::{GlobalKey, GlobalKeyRef};

impl PrivateKeyHolder {
    pub fn create_ethereum_v3(pk3: EthereumPk3) -> PrivateKeyHolder {
        PrivateKeyHolder {
            id: Uuid::new_v4(),
            pk: PrivateKeyType::EthereumPk(pk3),
            created_at: Utc::now(),
        }
    }

    #[cfg(test)]
    pub fn generate_ethereum_raw(password: &str) -> Result<PrivateKeyHolder, CryptoError> {
        let pk = core_PK::gen();
        PrivateKeyHolder::create_ethereum_raw(pk.0.to_vec(), password, None)
    }

    pub fn create_ethereum_raw(
        pk: Vec<u8>,
        password: &str,
        global: Option<GlobalKey>
    ) -> Result<PrivateKeyHolder, CryptoError> {
        let parsed = core_PK::try_from(pk.as_slice())
            .map_err(|_| CryptoError::InvalidKey)?;
        let encrypted = EthereumPk3 {
            address: Some(parsed.to_address()),
            key: Encrypted::encrypt(pk, password.as_bytes(), global)?,
        };
        Ok(PrivateKeyHolder::create_ethereum_v3(encrypted))
    }

    pub fn get_ethereum_address(&self) -> Option<EthereumAddress> {
        match &self.pk {
            PrivateKeyType::EthereumPk(e) => e.address,
        }
    }

    pub fn decrypt(&self, password: &[u8], global: Option<GlobalKey>) -> Result<Vec<u8>, CryptoError> {
        match &self.pk {
            PrivateKeyType::EthereumPk(ethereum) => ethereum.key.decrypt(password, global),
        }
    }
}
