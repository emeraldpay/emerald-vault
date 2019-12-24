use rocksdb::{DB, IteratorMode, Options};
use crate::migration::source::json_data::{KeyFileV2, CryptoTypeV2, AddressBookItem};
use crate::migration::types::{Migrate, MigrationResult, MigrationError};
use std::path::{PathBuf, Path};
use uuid::Uuid;
use std::convert::TryFrom;
use std::str::{from_utf8};
use crate::{
    util,
    address::Address,
    storage::{
        vault::VaultStorage,
        archive::Archive,
        addressbook::AddressBookmark,
        vault::VaultAccess
    },
    core::chains::{Blockchain, EthereumChainId},
    structs::{
        types::HasUuid,
        pk::{PrivateKeyHolder, PrivateKeyType, EthereumPk3},
        crypto::Encrypted,
        wallet::{Wallet, WalletAccount, PKType},
        book::{BookmarkDetails, AddressRef}
    }
};
use std::fs;
use crate::migration::source::common::add_to_vault;

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

    fn blockchain_path(&self, blockchain: &Blockchain) -> Option<PathBuf> {
        let chain_id = EthereumChainId::from(blockchain.clone());
        self.ethereum_path(&chain_id)
    }

    fn ethereum_path(&self, chain_id: &EthereumChainId) -> Option<PathBuf> {
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
    fn get_db(&mut self, path: PathBuf) -> Option<DB> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        let db = DB::open(&opts, path.join("keystore/.db").as_path())
            .map_err(|e| {
                &self.migration.error(format!("DB not opened {}", e.clone().into_string()));
                ()
            }).ok();
        db
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

    fn list_book(&mut self, blockchain: &Blockchain) -> Result<Vec<AddressBookItem>, String> {
        match self.blockchain_path(blockchain) {
            Some(path) => {
                let path = path.join("addressbook");
                let pattern = format!("{}/*.json", path.to_str().unwrap());
                let files = glob::glob(pattern.as_str()).unwrap();
                let mut result = Vec::new();
                for path in files {
                    let path = path.unwrap();
                    self.migration.info(format!("Process address book item {:?}", path));
                    match fs::read(path.clone()) {
                        Ok(body) => {
                            match serde_json::from_slice::<AddressBookItem>(body.as_slice()) {
                                Ok(parsed) => result.push(parsed),
                                Err(_) => self.migration.warn(format!("Invalid address book data in {:?}", path.file_name().unwrap()))
                            }
                        },
                        Err(_) => self.migration.warn(format!("Failed to read address book item from {:?}", path.file_name().unwrap()))
                    }
                }
                Ok(result)
            },
            None => {
                Ok(vec![])
            }
        }
    }

    fn migrate_wallets(&mut self, vault: &VaultStorage, created_wallets: &mut Vec<Uuid>, blockchain: &Blockchain) -> bool {
        let mut migrated = false;
        let path = self.blockchain_path(blockchain);
        if path.is_none() {
            return false;
        }
        let path = path.unwrap();
        match self.get_db(path) {
            Some(db) => {
                let accounts = self.list_accounts(db, &vault.archive)
                    .map_err(|e| {
                        &self.migration.error(format!("Failed to read accounts {}", e));
                    });
                if accounts.is_ok() {
                    let accounts = accounts.unwrap();
                    &self.migration.info(format!("Accounts to migrate: {}", accounts.len()));
                    accounts.iter().for_each(|kf| {
                        let address = match kf.address {
                            Some(a) => a.to_string(),
                            None => "UNKNOWN".to_string()
                        };
                        &self.migration.info(format!("Migrate key {}", address));
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

        migrated
    }

    fn migrate_addressbook(&mut self, vault: &VaultStorage, blockchain: &Blockchain) -> bool {
        let mut migrated = false;
        let items = self.list_book(&blockchain);
        if items.is_err() {
            &self.migration.warn(format!("Failed to read Address Book for {:?}", blockchain));
            return false
        }
        let items = items.unwrap();
        let book = vault.addressbook();
        for item in items {
            migrated = true;
            book.add(AddressBookmark {
                id: Uuid::new_v4(),
                details: BookmarkDetails {
                    blockchain: blockchain.clone(),
                    label: item.name,
                    description: item.description,
                    address: AddressRef::EthereumAddress(item.address)
                }
            });
        }
        migrated
    }
}

impl Migrate for V2Storage {

    fn migrate<P>(&mut self, target: P) -> Result<&MigrationResult, MigrationError>
        where P: AsRef<Path> {
        self.migration.info("Start migration from Vault V2".to_string());
        let supported_blockchains = vec![
            Blockchain::EthereumClassic, Blockchain::Ethereum,
            Blockchain::MordenTestnet, Blockchain::KovanTestnet
        ];
        let vault = VaultStorage::create(target)?;
        let mut created_wallets = Vec::new();
        let mut moved = 0;

        supported_blockchains.iter().for_each(|blockchain| {
            // Migrate all data for a single blockchain
            self.migration.info(format!("Migrate {:?}", blockchain));
            let migrated_keys = self.migrate_wallets(&vault, &mut created_wallets, blockchain);
            let migrated_book = self.migrate_addressbook(&vault, blockchain);
            self.migration.info(format!("Done migrating {:?}", blockchain));

            // RocksDB locks database, so move it to archive after DB object is destroyed
            if migrated_keys || migrated_book {
                self.migration.info(format!("Moving to archive keys for {:?}", blockchain));
                match self.blockchain_path(blockchain) {
                    Some(path) => { vault.archive.submit(path); },
                    None => {}
                }
                moved += 1;
            }
        });

        let unsupported_blockchains = vec![
            EthereumChainId::Rinkeby, EthereumChainId::Rootstock, EthereumChainId::RootstockTestnet, EthereumChainId::Ropsten
        ];

        unsupported_blockchains.iter().for_each(|blockchain| {
            match self.ethereum_path(blockchain) {
                Some(path) => {
                    self.migration.warn(format!("Archive unsupported {:?}", blockchain));
                    match self.get_db(path.clone()) {
                        Some(db) => {
                            match self.list_accounts(db, &vault.archive) {
                                Ok(items) => {
                                    for item in items {
                                        self.migration.warn(
                                            format!("Extracted a key file and moved to archive as JSON files. Please import {}.json manually if you want to use it with another blockchain",
                                                    item.uuid.to_string()
                                            )
                                        )
                                    }
                                },
                                Err(_) => self.migration.warn("Has broken database. Ignoring".to_string())
                            }
                        },
                        None => {}
                    }
                    vault.archive.submit(path);
                },
                None => {}
            }
        });

        self.migration.info("Migration finished".to_string());
        self.migration.set_wallets(created_wallets);
        if moved > 0 || self.migration.has_log() {
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
