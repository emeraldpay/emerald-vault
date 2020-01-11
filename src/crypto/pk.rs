use uuid::Uuid;
use crate::{
    structs::{
        pk::{PrivateKeyHolder, EthereumPk3, PrivateKeyType},
        crypto::Encrypted
    },
    crypto::error::CryptoError,
    core::{Address, PrivateKey as core_PK}
};

impl PrivateKeyHolder {

    pub fn create_ethereum_v3(pk3: EthereumPk3) -> PrivateKeyHolder {
        PrivateKeyHolder {
            id: Uuid::new_v4(),
            pk: PrivateKeyType::EthereumPk(pk3)
        }
    }

    pub fn create_ethereum_raw(pk: Vec<u8>, password: &str) -> Result<PrivateKeyHolder, CryptoError> {
        let parsed = core_PK::try_from(&pk).map_err(|_| CryptoError::InvalidKey)?;
        let encrypted = EthereumPk3 {
            address: Some(parsed.to_address()),
            key: Encrypted::encrypt(pk, password)?
        };
        Ok(PrivateKeyHolder::create_ethereum_v3(encrypted))
    }

    pub fn get_ethereum_address(&self) -> Option<Address> {
        match &self.pk {
            PrivateKeyType::EthereumPk(e) => e.address
        }
    }

    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, CryptoError> {
        match &self.pk {
            PrivateKeyType::EthereumPk(ethereum) => ethereum.key.decrypt(password)
        }
    }
}
