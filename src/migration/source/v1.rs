use std::fs::{read_dir, File};
use uuid::Uuid;
use std::path::{PathBuf, Path};
use std::io::Read;
use crate::{
    storage::vault::VaultStorage,
    core::chains::{Blockchain, EthereumChainId},
    migration::types::{Migrate, MigrationError},
    migration::types::MigrationResult,
    migration::source::common::add_to_vault
};
use std::fs;
use crate::migration::source::json_data::SerializableKeyFileCoreV2;

pub struct V1Storage {
    /// Parent directory for storage
    dir: PathBuf,
    migration: MigrationResult
}

impl V1Storage {

    pub fn create<P>(source: P) -> V1Storage
        where P: AsRef<Path> {
        V1Storage {
            dir: PathBuf::from(source.as_ref()),
            migration: MigrationResult::default()
        }
    }

    fn blockchain_path(&self, blockchain: &Blockchain) -> Option<PathBuf> {
        let chain_id = EthereumChainId::from(blockchain.clone());
        self.ethereum_path(&chain_id)
    }

    fn ethereum_path(&self, chain_id: &EthereumChainId) -> Option<PathBuf> {
        let base = self.dir
            .join(chain_id.get_path_element());
        if base.exists() && base.is_dir() {
            Some(base)
        } else {
            None
        }
    }

    fn migrate_wallets(&mut self, vault: &VaultStorage, created_wallets: &mut Vec<Uuid>, blockchain: &Blockchain) -> bool {
        let mut migrated = false;
        let path = self.blockchain_path(blockchain);
        if path.is_none() {
            return false;
        }
        let path = path.unwrap();
        let pattern = format!("{}/*.json", path.to_str().unwrap());
        let files = glob::glob(pattern.as_str()).unwrap();
        for path in files {
            let path = path.unwrap();
            self.migration.info(format!("Process Key File {:?}", path));
            match fs::read(path.clone()) {
                Ok(body) => {
                    match serde_json::from_slice::<SerializableKeyFileCoreV2>(body.as_slice()) {
                        Ok(parsed) => {
                            match add_to_vault(blockchain.clone(), &vault, &parsed.into()) {
                                Ok(id) => {
                                    created_wallets.push(id);
                                    migrated = true;
                                },
                                Err(msg) => {
                                    self.migration.error(format!("Not added to vault {}", msg));
                                }
                            }
                        },
                        Err(_) => self.migration.warn(format!("Invalid Key File in {:?}", path.file_name().unwrap()))
                    }
                },
                Err(_) => self.migration.warn(format!("Failed to Key File from {:?}", path.file_name().unwrap()))
            }
        }


        migrated
    }
}

impl Migrate for V1Storage {
    fn migrate<P>(&mut self, target: P) -> Result<&MigrationResult, MigrationError> where P: AsRef<Path> {
        self.migration.info("Start migration from Vault V1".to_string());
        let supported_blockchains = vec![
            Blockchain::EthereumClassic,
            Blockchain::MordenTestnet,
        ];
        let vault = VaultStorage::create(target)?;
        let mut created_wallets = Vec::new();
        let mut moved = 0;

        supported_blockchains.iter().for_each(|blockchain| {
            // Migrate all data for a single blockchain
            &self.migration.info(format!("Migrate {:?}", blockchain));
            let migrated_keys = self.migrate_wallets(&vault, &mut created_wallets, blockchain);
            &self.migration.info(format!("Done migrating {:?}", blockchain));

            if migrated_keys {
                &self.migration.info(format!("Moving to archive keys for {:?}", blockchain));
                match self.blockchain_path(blockchain) {
                    Some(path) => { vault.archive.submit(path); },
                    None => {}
                }
                moved += 1;
            }
        });

        self.migration.info("Migration finished".to_string());
        self.migration.set_wallets(created_wallets);
        if moved > 0 || self.migration.has_log() {
            let mut readme = String::new();
            readme.push_str("= Migration From Vault V1 Storage\n\n");
            readme.push_str("\n== DESCRIPTION\n\n");
            readme.push_str("Necessary upgrade of the Vault storage from Version 1 to Version 3\n");
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
