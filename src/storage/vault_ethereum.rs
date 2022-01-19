use std::convert::TryFrom;

use hdpath::StandardHDPath;
use uuid::Uuid;

use crate::blockchain::{
    chains::Blockchain,
    ethereum::{EthereumPrivateKey, EthereumAddress},
};
use crate::convert::error::ConversionError;
use crate::sign::bip32::generate_key;
use crate::storage::error::VaultError;
use crate::storage::vault::{VaultAccessByFile};
use crate::structs::book::AddressRef;
use crate::structs::seed::{Seed, SeedRef, SeedSource};
use crate::structs::wallet::{PKType, Wallet, WalletEntry};
use std::sync::Arc;
use crate::structs::pk::PrivateKeyHolder;
use crate::convert::json::keyfile::EthereumJsonV3File;
use std::time::SystemTime;
use crate::structs::types::HasUuid;
use crate::blockchain::chains::BlockchainType;
use emerald_hwkey::ledger::manager::LedgerKey;
use std::str::FromStr;
use emerald_hwkey::ledger::app_ethereum::EthereumApp;
use emerald_hwkey::ledger::traits::LedgerApp;

pub struct AddEthereumEntry {
    keys: Arc<dyn VaultAccessByFile<PrivateKeyHolder>>,
    seeds: Arc<dyn VaultAccessByFile<Seed>>,
    wallets: Arc<dyn VaultAccessByFile<Wallet>>,
    wallet_id: Uuid,
}

impl AddEthereumEntry {
    pub fn new(wallet_id: &Uuid,
               keys: Arc<dyn VaultAccessByFile<PrivateKeyHolder>>,
               seeds: Arc<dyn VaultAccessByFile<Seed>>,
               wallets: Arc<dyn VaultAccessByFile<Wallet>>, ) -> AddEthereumEntry {
        AddEthereumEntry {
            wallet_id: wallet_id.clone(),
            keys,
            seeds,
            wallets,
        }
    }

    pub fn json(
        &self,
        json: &EthereumJsonV3File,
        blockchain: Blockchain,
    ) -> Result<usize, VaultError> {
        let mut wallet = self.wallets.get(self.wallet_id.clone())?;
        let mut pk = PrivateKeyHolder::try_from(json)?;
        let pk_id = pk.generate_id();
        self.keys.add(pk)?;
        let id = wallet.next_entry_id();
        wallet.entries.push(WalletEntry {
            id,
            blockchain,
            address: json.address.map(|a| AddressRef::EthereumAddress(a)),
            key: PKType::PrivateKeyRef(pk_id),
            receive_disabled: false,
            label: json.name.clone(),
            created_at: SystemTime::now().into(),
        });
        wallet.entry_seq = id + 1;
        self.wallets.update(wallet.clone())?;
        Ok(id)
    }

    pub fn raw_pk(
        &mut self,
        pk: Vec<u8>,
        password: &str,
        blockchain: Blockchain,
    ) -> Result<usize, VaultError> {
        let mut wallet = self.wallets.get(self.wallet_id.clone())?;
        let pk = PrivateKeyHolder::create_ethereum_raw(pk, password)
            .map_err(|_| VaultError::InvalidDataError("Invalid PrivateKey".to_string()))?;
        let pk_id = pk.get_id();
        let address = pk
            .get_ethereum_address()
            .clone()
            .map(|a| AddressRef::EthereumAddress(a));
        let id = wallet.next_entry_id();
        self.keys.add(pk)?;
        wallet.entries.push(WalletEntry {
            id,
            blockchain,
            address,
            key: PKType::PrivateKeyRef(pk_id),
            ..WalletEntry::default()
        });
        wallet.entry_seq = id + 1;
        self.wallets.update(wallet.clone())?;
        Ok(id)
    }

    pub fn seed_hd(
        &self,
        seed_id: Uuid,
        hd_path: StandardHDPath,
        blockchain: Blockchain,
        password: Option<String>,
        expected_address: Option<EthereumAddress>,
    ) -> Result<usize, VaultError> {
        if blockchain.get_type() != BlockchainType::Ethereum {
            return Err(VaultError::IncorrectBlockchainError)
        }
        let seed = self.seeds.get(seed_id)?;
        let address = match seed.source {
            SeedSource::Bytes(seed) => {
                if password.is_none() {
                    return Err(VaultError::PasswordRequired);
                }
                let seed = seed.decrypt(password.unwrap().as_str())?;
                let key = generate_key(&hd_path, seed.as_slice())?;
                let ephemeral_pk = EthereumPrivateKey::try_from(key)?;
                Some(ephemeral_pk.to_address())
            }
            SeedSource::Ledger(_) => {
                // try to verify address if Ledger is currently connected
                let manager = LedgerKey::new_connected().map_err(|_| VaultError::PrivateKeyUnavailable)?;
                let ethereum_app = EthereumApp::new(&manager);
                if ethereum_app.is_open().is_none() {
                    None
                } else {
                    ethereum_app.get_address(&hd_path, false)
                        .ok()
                        .and_then(|a| EthereumAddress::from_str(a.address.as_str()).ok())
                }
            }
        };

        if expected_address.is_some() && address.is_some() && address != expected_address {
            return Err(VaultError::InvalidDataError(
                "Different address".to_string(),
            ));
        }

        let mut wallet = self.wallets.get(self.wallet_id.clone())?;
        let id = wallet.next_entry_id();
        wallet.entries.push(WalletEntry {
            id,
            blockchain,
            address: address
                .or(expected_address)
                .map(|a| AddressRef::EthereumAddress(a)),
            key: PKType::SeedHd(SeedRef {
                seed_id: seed_id.clone(),
                hd_path: StandardHDPath::try_from(hd_path.to_string().as_str()).map_err(|_| {
                    VaultError::ConversionError(ConversionError::InvalidFieldValue(
                        "hd_path".to_string(),
                    ))
                })?,
            }),
            ..WalletEntry::default()
        });
        wallet.entry_seq = id + 1;
        self.wallets.update(wallet.clone())?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        convert::json::keyfile::EthereumJsonV3File,
        structs::pk::{EthereumPk3, PrivateKeyHolder},
        tests::*,
    };
    use tempdir::TempDir;
    use crate::storage::vault::VaultStorage;

    #[test]
    fn add_single_pk() {
        let json = r#"
            {
                "version": 3,
                "id": "305f4853-80af-4fa6-8619-6f285e83cf28",
                "address": "6412c428fc02902d137b60dc0bd0f6cd1255ea99",
                "name": "Hello",
                "description": "World!!!!",
                "visible": true,
                "crypto": {
                    "cipher": "aes-128-ctr",
                    "cipherparams": {"iv": "e4610fb26bd43fa17d1f5df7a415f084"},
                    "ciphertext": "dc50ab7bf07c2a793206683397fb15e5da0295cf89396169273c3f49093e8863",
                    "kdf": "scrypt",
                    "kdfparams": {
                        "dklen": 32,
                        "salt": "86c6a8857563b57be9e16ad7a3f3714f80b714bcf9da32a2788d695a194f3275",
                        "n": 1024,
                        "r": 8,
                        "p": 1
                    },
                    "mac": "8dfedc1a92e2f2ca1c0c60cd40fabb8fb6ce7c05faf056281eb03e0a9996ecb0"
                }
            }
        "#;
        let json = EthereumJsonV3File::try_from(json.to_string()).expect("JSON not parsed");
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");

        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let vault_pk = vault.keys();
        let pk = PrivateKeyHolder::create_ethereum_v3(EthereumPk3::try_from(&json).unwrap());
        let pk_id = pk.id;
        let saved = vault_pk.add(pk);
        assert!(saved.is_ok());

        let list = vault_pk.list().unwrap();
        assert_eq!(1, list.len());
        assert_eq!(pk_id, list[0]);

        vault_pk.get(pk_id).unwrap();
    }

    #[test]
    fn remove_after_adding() {
        let json = r#"
            {
                "version": 3,
                "id": "305f4853-80af-4fa6-8619-6f285e83cf28",
                "address": "6412c428fc02902d137b60dc0bd0f6cd1255ea99",
                "name": "Hello",
                "description": "World!!!!",
                "visible": true,
                "crypto": {
                    "cipher": "aes-128-ctr",
                    "cipherparams": {"iv": "e4610fb26bd43fa17d1f5df7a415f084"},
                    "ciphertext": "dc50ab7bf07c2a793206683397fb15e5da0295cf89396169273c3f49093e8863",
                    "kdf": "scrypt",
                    "kdfparams": {
                        "dklen": 32,
                        "salt": "86c6a8857563b57be9e16ad7a3f3714f80b714bcf9da32a2788d695a194f3275",
                        "n": 1024,
                        "r": 8,
                        "p": 1
                    },
                    "mac": "8dfedc1a92e2f2ca1c0c60cd40fabb8fb6ce7c05faf056281eb03e0a9996ecb0"
                }
            }
        "#;
        let json = EthereumJsonV3File::try_from(json.to_string()).expect("JSON not parsed");
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let vault_pk = vault.keys();
        let pk = PrivateKeyHolder::create_ethereum_v3(EthereumPk3::try_from(&json).unwrap());
        let exp_id = pk.id;
        let saved = vault_pk.add(pk);
        assert!(saved.is_ok());

        let list = vault_pk.list().unwrap();
        assert_eq!(1, list.len());

        let deleted = vault_pk.remove(exp_id);
        assert!(deleted.is_ok());
        assert!(deleted.unwrap());

        let list = vault_pk.list().unwrap();
        assert_eq!(0, list.len());
    }
}
