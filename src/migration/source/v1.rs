use crate::{
    blockchain::chains::Blockchain,
    migration::{
        source::{common::add_to_vault, json_data::SerializableKeyFileCoreV2},
        types::{Migrate, MigrationError, MigrationResult},
    },
    storage::{
        archive::{Archive, ArchiveType},
        vault::VaultStorage,
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub struct V1Storage {
    /// Parent directory for storage
    dir: PathBuf,
    migration: MigrationResult,
}

impl V1Storage {
    pub fn create<P>(source: P) -> V1Storage
    where
        P: AsRef<Path>,
    {
        V1Storage {
            dir: PathBuf::from(source.as_ref()),
            migration: MigrationResult::default(),
        }
    }

    fn blockchain_path(&self, blockchain: &Blockchain) -> Option<PathBuf> {
        let name = match blockchain {
            Blockchain::Ethereum => "eth",
            Blockchain::EthereumClassic => "mainnet",
            Blockchain::KovanTestnet => "kovan",
            _ => return None,
        };
        self.ethereum_path(name)
    }

    fn ethereum_path(&self, name: &str) -> Option<PathBuf> {
        let base = self.dir.join(name);
        if base.exists() && base.is_dir() {
            Some(base)
        } else {
            None
        }
    }

    fn migrate_wallets(
        &mut self,
        vault: &VaultStorage,
        created_wallets: &mut Vec<Uuid>,
        blockchain: &Blockchain,
    ) -> bool {
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
                                }
                                Err(msg) => {
                                    self.migration.error(format!("Not added to vault {}", msg));
                                }
                            }
                        }
                        Err(_) => self.migration.warn(format!(
                            "Invalid Key File in {:?}",
                            path.file_name().unwrap()
                        )),
                    }
                }
                Err(_) => self.migration.warn(format!(
                    "Failed to Key File from {:?}",
                    path.file_name().unwrap()
                )),
            }
        }

        migrated
    }
}

impl Migrate for V1Storage {
    fn migrate<P>(&mut self, target: P) -> Result<&MigrationResult, MigrationError>
    where
        P: AsRef<Path>,
    {
        self.migration
            .info("Start migration from Vault V1".to_string());
        let supported_blockchains = vec![
            // V1 had only Morden and ETC Mainnet
            Blockchain::EthereumClassic,
        ];
        let vault = VaultStorage::create(target)?;
        let mut created_wallets = Vec::new();
        let mut moved = 0;

        let archive = Archive::create(vault.dir.clone(), ArchiveType::Migrate);

        supported_blockchains.iter().for_each(|blockchain| {
            // Migrate all data for a single blockchain
            let _ = &self.migration.info(format!("Migrate {:?}", blockchain));
            let migrated_keys = self.migrate_wallets(&vault, &mut created_wallets, blockchain);
            let _ = &self
                .migration
                .info(format!("Done migrating {:?}", blockchain));

            if migrated_keys {
                let _ = &self
                    .migration
                    .info(format!("Moving to archive keys for {:?}", blockchain));
                match self.blockchain_path(blockchain) {
                    Some(path) => {
                        let archived = archive.submit(path);
                        if archived.is_err() {
                            let _ = &self.migration.error(format!(
                                "Failed to add to archive. Error: {}",
                                archived.err().unwrap()
                            ));
                        }
                    }
                    None => {}
                };
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
            match archive.write("README.txt", readme.as_str()) {
                Err(e) => println!("ERROR Failed to write README. Error: {}", e),
                _ => {}
            };
        }

        Ok(&self.migration)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        blockchain::chains::Blockchain,
        migration::{
            source::v1::V1Storage,
            test_commons::{sort_wallets, unzip},
            types::Migrate,
        },
        storage::vault::VaultStorage,
        structs::{book::AddressRef, wallet::Wallet},
        EthereumAddress,
    };
    use std::str::FromStr;
    use tempdir::TempDir;

    #[test]
    fn migrate_basic() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();
        unzip(
            "./tests/migration/vault-0.10.1-migrate.zip",
            tmp_dir.clone(),
        );

        let mut storage = V1Storage::create(tmp_dir.join("vault-0.10.1-migrate"));
        let result = storage.migrate(tmp_dir.join("migrated")).unwrap();
        //        println!("Migrated:");
        //        show_dir(tmp_dir.clone(), None);
        //        println!("---");
        assert_eq!(result.wallets.len(), 2);

        let vault = VaultStorage::create(tmp_dir.join("migrated")).unwrap();
        let mut wallets = vault.wallets().list_entries().unwrap();
        sort_wallets(&mut wallets);

        assert_eq!(wallets.len(), 2);

        let eth_wallets: Vec<&Wallet> = wallets
            .iter()
            .filter(|w| w.get_entry(0).unwrap().blockchain == Blockchain::Ethereum)
            .collect();
        assert_eq!(eth_wallets.len(), 0);

        let etc_wallets: Vec<&Wallet> = wallets
            .iter()
            .filter(|w| w.get_entry(0).unwrap().blockchain == Blockchain::EthereumClassic)
            .collect();
        assert_eq!(etc_wallets.len(), 2);
        assert_eq!(
            etc_wallets[0].get_entry(0).unwrap().address,
            Some(AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x410891c20e253a2d284f898368860ec7ffa6153c").unwrap()
            ))
        );
        assert_eq!(
            etc_wallets[1].get_entry(0).unwrap().address,
            Some(AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x5b30de96fdf94ac6c5b4a8c243f991c649d66fa1").unwrap()
            ))
        );

        let kovan_wallets: Vec<&Wallet> = wallets
            .iter()
            .filter(|w| w.get_entry(0).unwrap().blockchain == Blockchain::KovanTestnet)
            .collect();
        assert_eq!(kovan_wallets.len(), 0);
    }
}
