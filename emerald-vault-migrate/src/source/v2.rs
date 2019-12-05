use rocksdb::{DB, IteratorMode, Options};
use crate::source::json_data::{KeyFileV2, CryptoTypeV2};
use crate::migration::types::{Migrate, MigrationResult, MigrationError};
use std::path::{PathBuf, Path};
use uuid::Uuid;
use std::convert::TryFrom;
use std::str::{from_utf8};
use emerald_vault_core::{
    util,
    address::Address,
    storage::vault::VaultStorage,
    core::chains::{Blockchain, EthereumChainId},
    convert::proto::{
        types::HasUuid,
        pk::{PrivateKeyHolder, PrivateKeyType, EthereumPk3},
        crypto::Encrypted,
        wallet::{Wallet, WalletAccount, AddressType, EthereumAddress}
    }
};
use emerald_vault_core::storage::archive::Archive;

/// Separator for data in RocksDB
/// `value = <filename> + SEPARATOR + <keyfile_json>`
///
const SEPARATOR: &str = "<|>";

pub struct V2Storage {
    dir: PathBuf,
    migration: MigrationResult
}

impl V2Storage {

    pub fn create<P>(source: P) -> V2Storage
        where P: AsRef<Path> {
        V2Storage {
            dir: PathBuf::from(source.as_ref()),
            migration: MigrationResult::default()
        }
    }

    /// Splits value into `filename` and `Keyfile` json
    fn split(val: &str) -> Result<(String, String), ()> {
        let arr: Vec<&str> = val.split(SEPARATOR).collect();
        let json = arr[1..arr.len()].join(SEPARATOR);

        Ok((arr[0].to_string(), json))
    }

    fn db_path(&self, blockchain: Blockchain) -> Option<PathBuf> {
        let chain_id = EthereumChainId::from(blockchain.clone());
        let base = self.dir
            .join(chain_id.get_path_element());
        let path = base.join("keystore/.db");
        if path.exists() && path.is_dir() {
            Some(base)
        } else {
            None
        }
    }

    /// Get DB for the specified blockchain, if it exists
    fn get_db(&mut self, blockchain: Blockchain) -> Option<DB> {
        match &self.db_path(blockchain) {
            Some(path) => {
                let mut opts = Options::default();
                opts.create_if_missing(false);
                let db = DB::open(&opts, path.join("keystore/.db").as_path())
                    .map_err(|e| {
                        &self.migration.error(format!("DB not opened {}", e.clone().into_string()));
                        ()
                    }).ok();
                db
            },
            None => None
        }
    }

    fn list_accounts(&mut self, db: DB, archive: &Archive) -> Result<Vec<KeyFileV2>, String> {
        let mut accounts = vec![];

        for (addr, val) in db.iterator(IteratorMode::Start) {
            let vec = from_utf8(&val).map_err(|e| "Not a string value")?;
            let (filename, json) = V2Storage::split(vec).map_err(|e| "Not a Vault value")?;
            &self.migration.info(format!("Process {}", filename));
            let mut copy = String::new();
            copy.push_str(filename.as_str());
            copy.push_str(".json");
            archive.write(copy.as_str(), json.as_str());
            match KeyFileV2::decode(&json) {
                Ok(kf) => { accounts.push(kf) },
                Err(e) => {
                    let data: [u8; 20] = util::to_arr(&*addr);
                    &self.migration.error(
                        format!(
                            "Invalid keystore file format for address: {}. Message: {}",
                            Address::from(data), e
                        )
                    );
                }
            }
        }

        Ok(accounts)
    }
}

fn extract_label(kf: &KeyFileV2) -> Option<String> {
    let mut result = String::new();
    match &kf.name {
        Some(name) => result.push_str(name.as_str()),
        None => {}
    }
    match &kf.visible {
        Some(visible) if !visible => {
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str("(legacy hidden)")
        },
        _ => {}
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// Creates Private Key and Wallet with that single key
fn add_to_vault(blockchain: Blockchain, vault: &VaultStorage, kf: &KeyFileV2) -> Result<Uuid, String> {
    let account = match &kf.crypto {
        CryptoTypeV2::Core(data) => {
            let pk = PrivateKeyHolder {
                id: Uuid::new_v4(),
                pk: PrivateKeyType::Ethereum(
                    EthereumPk3 {
                        address: Some(kf.address),
                        key: Encrypted::try_from(data).map_err(|e| "Failed to convert encrypted Private Key")?
                    }
                )
            };
            let pk_id = pk.get_id();
            vault.keys().add(pk).map_err(|e| "Failed to add converted Private Key to the Vault")?;
            WalletAccount {
                blockchain,
                address: AddressType::Ethereum(
                    EthereumAddress {
                        address: Some(kf.address),
                        key_id: pk_id
                    }
                )
            }
        },
        CryptoTypeV2::HdWallet(_) => unimplemented!()
    };
    let wallet = Wallet {
        id: Uuid::new_v4(),
        label: extract_label(kf),
        accounts: vec![account]
    };
    let wallet_id = wallet.get_id();
    vault.wallets().add(wallet);
    Ok(wallet_id)
}

impl Migrate for V2Storage {

    fn migrate<P>(&mut self, target: P) -> Result<&MigrationResult, MigrationError>
        where P: AsRef<Path> {
        &self.migration.info("Start migration".to_string());
        let supported_blockchains = vec![
            Blockchain::EthereumClassic, Blockchain::Ethereum,
            Blockchain::MordenTestnet, Blockchain::KovanTestnet
        ];
        let vault = VaultStorage::create(target)?;
        let mut created_wallets = Vec::new();
        let mut moved = 0;

        supported_blockchains.iter().for_each(|blockchain| {
            // Migrate all data for a single blockchain
            &self.migration.info(format!("Migrate {:?}", blockchain));
            let mut migrated = false;
            match self.get_db(blockchain.clone()) {
                Some(db) => {
                    let accounts = self.list_accounts(db, &vault.archive)
                        .map_err(|e| {
                            &self.migration.error(format!("Failed to read accounts {}", e));
                        });
                    if accounts.is_ok() {
                        let accounts = accounts.unwrap();
                        &self.migration.info(format!("Accounts to migrate: {}", accounts.len()));
                        accounts.iter().for_each(|kf| {
                            &self.migration.info(format!("Migrate key {}", kf.address.to_string()));
                            match add_to_vault(blockchain.clone(), &vault, kf) {
                                Ok(id) => {
                                    created_wallets.push(id);
                                },
                                Err(msg) => {
                                    &self.migration.error(format!("Not added to vault {}", msg));
                                }
                            }
                        });
                        migrated = true
                    };
                },
                None => {
                    // It happens only if the directory was manually deleted
                    &self.migration.warn(format!("No DB for {:?}", blockchain));
                }
            }
            // RocksDB locks database, so move it to archvie after DB object is destroyed
            if migrated {
                &self.migration.info(format!("Moving to archive keys for {:?}", blockchain));
                match self.db_path(blockchain.clone()) {
                    Some(path) => { vault.archive.submit(path); },
                    None => {}
                }
                moved += 1;
            }
            &self.migration.info(format!("Done migrating {:?}", blockchain));
        });

        &self.migration.info("Migration finished".to_string());
        &self.migration.set_wallets(created_wallets);
        if moved > 0 {
            let mut readme = String::new();
            readme.push_str("= Migration From Vault V2 Storage\n\n");
            readme.push_str("\n== DESCRIPTION\n\n");
            readme.push_str("Necessary upgrade of the Vault storage from Version 2 to Version 3\n");
            readme.push_str("\n== LOG\n\n");
            readme.push_str(&self.migration.logs_to_string().as_str());
            match vault.archive.write("README.txt", readme.as_str()) {
                Err(e) => {
                    println!("ERROR Failed to write README. Error: {}", e)
                },
                _ => {}
            };
        }

        Ok(&self.migration)
    }
}
