use crate::storage::error::VaultError;
use crate::{EthereumPrivateKey, to_arr};
use crate::structs::wallet::PKType;
use std::convert::{TryFrom, TryInto};
use crate::structs::seed::SeedSource;
use crate::sign::bip32::generate_key;
use crate::storage::vault::VaultStorage;
use bitcoin::util::bip32::ExtendedPrivKey;
use secp256k1::SecretKey;
use hdpath::StandardHDPath;
use bitcoin::{PrivateKey, Network};

pub enum PrivateKeySource {
    Base(SecretKey),
    Extended(ExtendedPrivKey),
}

impl PrivateKeySource {
    pub fn into_secret(self) -> SecretKey {
        match self {
            PrivateKeySource::Base(sk) => sk,
            PrivateKeySource::Extended(ext) => ext.private_key.key
        }
    }

    pub fn into_bitcoin_key(self, network: &Network) -> PrivateKey {
        match self {
            PrivateKeySource::Base(key) => PrivateKey {
                compressed: true,
                network: network.clone(),
                key,
            },
            PrivateKeySource::Extended(ext) => ext.private_key
        }
    }
}

impl SeedSource {
    pub fn get_pk(&self, password: Option<String>, hd_path: &StandardHDPath) -> Result<PrivateKeySource, VaultError> {
        match self {
            SeedSource::Bytes(bytes) => {
                match password {
                    None => Err(VaultError::PasswordRequired),
                    Some(password) => {
                        let seed_key = bytes.decrypt(password.as_str())?;
                        let key = generate_key(&hd_path, &seed_key)?;
                        Ok(PrivateKeySource::Extended(key))
                    }
                }
            }
            SeedSource::Ledger(_) => Err(VaultError::PrivateKeyUnavailable),
        }
    }
}

impl PKType {
    pub fn get_pk(&self, vault: &VaultStorage, password: Option<String>) -> Result<PrivateKeySource, VaultError> {
        match &self {
            PKType::PrivateKeyRef(pk) => {
                let key = vault.keys().get(pk.clone())?;
                let key = match password {
                    None => return Err(VaultError::PasswordRequired),
                    Some(password) => key.decrypt(password.as_str())?
                };
                let key = SecretKey::from_slice(key.as_slice())
                    .map_err(|e| VaultError::InvalidPrivateKey)?;
                Ok(PrivateKeySource::Base(key))
            }
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(seed.seed_id.clone())?;
                let hd_path = StandardHDPath::try_from(seed.hd_path.to_string().as_str())?;
                seed_details.source.get_pk(password, &hd_path)
            }
        }
    }

    pub fn get_ethereum_pk(&self, vault: &VaultStorage, password: Option<String>) -> Result<EthereumPrivateKey, VaultError> {
        let source = self.get_pk(vault, password)?;
        Ok(EthereumPrivateKey::from(source.into_secret()))
    }
}
