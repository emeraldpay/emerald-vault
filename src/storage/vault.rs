use crate::hdwallet::bip32::{generate_key, HDPath};
use crate::storage::addressbook::AddressbookStorage;
use crate::storage::archive::ArchiveType;
use crate::structs::seed::{SeedRef, SeedSource};
use crate::{
    chains::Blockchain,
    convert::{error::ConversionError, json::keyfile::EthereumJsonV3File},
    storage::{archive::Archive, error::VaultError},
    structs::{
        pk::PrivateKeyHolder,
        seed::Seed,
        types::HasUuid,
        wallet::{PKType, Wallet, WalletAccount},
    },
    Address,
};
use regex::Regex;
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;
use hdpath::StandardHDPath;

pub struct VaultStorage {
    pub dir: PathBuf,

    keys: Arc<dyn VaultAccess<PrivateKeyHolder>>,
    wallets: Arc<dyn VaultAccess<Wallet>>,
    seeds: Arc<dyn VaultAccess<Seed>>,
}

struct StandardVaultFiles {
    dir: PathBuf,
    suffix: String,
}

/// Main interface to the Emerald Vault storage
impl VaultStorage {
    pub fn keys(&self) -> Arc<dyn VaultAccess<PrivateKeyHolder>> {
        self.keys.clone()
    }
    pub fn wallets(&self) -> Arc<dyn VaultAccess<Wallet>> {
        self.wallets.clone()
    }
    pub fn seeds(&self) -> Arc<dyn VaultAccess<Seed>> {
        self.seeds.clone()
    }
    pub fn create_new(&self) -> CreateWallet {
        CreateWallet {
            keys: self.keys(),
            wallets: self.wallets(),
            seeds: self.seeds(),
        }
    }
    pub fn addressbook(&self) -> AddressbookStorage {
        AddressbookStorage::from_path(self.dir.clone().join("addressbook.csv"))
    }
    pub fn add_account(&self, wallet_id: Uuid) -> AddAccount {
        AddAccount {
            keys: self.keys().clone(),
            seeds: self.seeds().clone(),
            wallets: self.wallets().clone(),
            wallet_id,
        }
    }

    /// Check the Vault directory and revert stale backups. I.e., restore from a situation when
    /// file was moved to backup, but update has failed because of some reasons, as a result there is no usable file,
    /// only backup. If both original file and backup exists, then backup file is going to be moved to archive
    pub fn revert_backups(&self) -> Result<usize, VaultError> {
        lazy_static! {
            static ref BACKUP_RE: Regex = Regex::new(r"(?P<id>[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\.(?P<suffix>[a-z]+).bak").unwrap();
        }

        let archive = Archive::create(&self.dir, ArchiveType::Recover);

        let dir = fs::read_dir(&self.dir)?;
        let backups: Vec<PathBuf> = dir
            .filter(|i| i.is_ok())
            .map(|i| i.unwrap())
            .map(|i| i.path())
            .filter(|i| i.is_file())
            .filter(|i| match i.file_name() {
                Some(fname) => match fname.to_str() {
                    Some(fname) => BACKUP_RE.is_match(fname),
                    None => false,
                },
                None => false,
            })
            .collect();

        let mut count = 0;
        let mut count_archived = 0;

        backups.iter().for_each(|f| {
            match f.file_stem() {
                Some(orig) => {
                    let orig = self.dir.join(orig);
                    // double check that we have two different files
                    if &orig == f {
                        error!(
                            "Invalid state. Backup is same as source file. {:?} == {:?}",
                            orig, f
                        )
                    } else {
                        count += 1;
                        if !&orig.exists() {
                            if fs::rename(f, orig.clone()).is_err() {
                                warn!("Failed to rename backup file {:?} to {:?}", f, orig)
                            }
                        } else {
                            count_archived += 1; // count it regardless the status of the following submit, at least we'll have a readme as a marker
                            if archive.submit(f).is_err() {
                                warn!("Failed to move backup to archive {:?}", f)
                            }
                        }
                    }
                }
                None => warn!("Unsupported filename: {:?}", f),
            }
        });

        if count_archived > 0 {
            archive.finalize()
        }

        Ok(count)
    }
}

/// Safe update of a file, with making a .bak copy of the existing file, writing new content and
/// only then removing initial data. If it fails at some point, or backup is already exists, it
/// returns error
fn safe_update<P: AsRef<Path>, C: AsRef<[u8]>>(
    file: P,
    new_content: C,
    archive: Option<&Archive>,
) -> Result<(), VaultError> {
    let file = file.as_ref();
    if !file.exists() || file.is_dir() {
        return Err(VaultError::FilesystemError(
            "Original file doesn't exist or invalid".to_string(),
        ));
    }

    // bak file should keep original extension as part of it, it allows to recover original file,
    // because file extension is the type of data
    // so something.key -> something.key.bak
    let current_extension = file
        .extension()
        .ok_or(VaultError::FilesystemError("Invalid extension".to_string()))?
        .to_str()
        .unwrap();
    let mut bak_extension = String::with_capacity(current_extension.len() + 4);
    bak_extension.push_str(current_extension);
    bak_extension.push_str(".bak");
    let bak_file_name = file.with_extension(bak_extension);
    if bak_file_name.exists() {
        println!("bak {:?}", bak_file_name);
        return Err(VaultError::FilesystemError("Already updating".to_string()));
    }

    if fs::rename(file, &bak_file_name).is_err() {
        return Err(VaultError::FilesystemError(
            "Failed to create backup".to_string(),
        ));
    }
    if fs::write(file, new_content).is_err() {
        // FAILURE! Revert back!
        if fs::remove_file(file).is_err() {
            println!("Failed to remove {:?}", file)
        }
        if fs::rename(&bak_file_name, file).is_err() {
            return Err(VaultError::FilesystemError(
                "Failed to create update filesystem, and data stuck with backup".to_string(),
            ));
        }
        return Err(VaultError::FilesystemError("Failed to update".to_string()));
    }
    let archived = match archive {
        Some(archive) => match archive.submit(bak_file_name.clone()) {
            Ok(()) => true,
            Err(e) => {
                error!("Failed to archive backup file. {}", e);
                false
            }
        },
        None => false,
    };
    if !archived {
        if fs::remove_file(bak_file_name).is_err() {
            error!("Failed to delete backup file")
        }
    }
    Ok(())
}

fn try_vault_file(file: &Path, suffix: &str) -> Result<Uuid, ()> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(?P<id>[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\.(?P<suffix>[a-z]+)").unwrap();
    }

    match file.file_name() {
        Some(name) => {
            let file_name = name.to_str().unwrap();
            match RE.captures(file_name) {
                Some(caps) => {
                    let act_suffix = caps.name("suffix").unwrap().as_str();
                    if act_suffix.eq(suffix) {
                        let id: &str = caps.name("id").unwrap().as_str();
                        let uuid = Uuid::from_str(id).unwrap();
                        if format!("{}.{}", &uuid, suffix).eq(file_name) {
                            Ok(uuid)
                        } else {
                            Err(())
                        }
                    } else {
                        Err(())
                    }
                }
                None => Err(()),
            }
        }
        None => Err(()),
    }
}

pub struct CreateWallet {
    keys: Arc<dyn VaultAccess<PrivateKeyHolder>>,
    wallets: Arc<dyn VaultAccess<Wallet>>,
    seeds: Arc<dyn VaultAccess<Seed>>,
}

impl CreateWallet {
    pub fn ethereum(
        &self,
        json: &EthereumJsonV3File,
        blockchain: Blockchain,
    ) -> Result<Uuid, VaultError> {
        let mut pk = PrivateKeyHolder::try_from(json)?;
        pk.generate_id();
        let wallet = Wallet {
            label: json.name.clone(),
            accounts: vec![WalletAccount {
                id: 0,
                blockchain,
                address: json.address,
                key: PKType::PrivateKeyRef(pk.get_id()),
                receive_disabled: false,
            }],
            ..Wallet::default()
        };
        let result = wallet.get_id();
        self.keys.add(pk)?;
        self.wallets.add(wallet)?;
        Ok(result)
    }

    pub fn raw_pk(
        &self,
        pk: Vec<u8>,
        password: &str,
        blockchain: Blockchain,
    ) -> Result<Uuid, VaultError> {
        let pk = PrivateKeyHolder::create_ethereum_raw(pk, password)
            .map_err(|_| VaultError::InvalidDataError("Invalid PrivateKey".to_string()))?;
        let wallet = Wallet {
            accounts: vec![WalletAccount {
                id: 0,
                blockchain,
                address: pk.get_ethereum_address(),
                key: PKType::PrivateKeyRef(pk.get_id()),
                receive_disabled: false,
            }],
            ..Wallet::default()
        };
        let result = wallet.get_id();
        self.keys.add(pk)?;
        self.wallets.add(wallet)?;
        Ok(result)
    }
}

pub struct AddAccount {
    keys: Arc<dyn VaultAccess<PrivateKeyHolder>>,
    seeds: Arc<dyn VaultAccess<Seed>>,
    wallets: Arc<dyn VaultAccess<Wallet>>,
    wallet_id: Uuid,
}

impl AddAccount {
    pub fn ethereum(
        &self,
        json: &EthereumJsonV3File,
        blockchain: Blockchain,
    ) -> Result<usize, VaultError> {
        let mut wallet = self.wallets.get(self.wallet_id.clone())?;
        let mut pk = PrivateKeyHolder::try_from(json)?;
        let pk_id = pk.generate_id();
        self.keys.add(pk)?;
        let id = wallet.get_account_id();
        wallet.accounts.push(WalletAccount {
            id,
            blockchain,
            address: json.address,
            key: PKType::PrivateKeyRef(pk_id),
            receive_disabled: false,
        });
        wallet.account_seq = id + 1;
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
        let address = pk.get_ethereum_address().clone();
        let id = wallet.get_account_id();
        self.keys.add(pk)?;
        wallet.accounts.push(WalletAccount {
            id,
            blockchain,
            address,
            key: PKType::PrivateKeyRef(pk_id),
            receive_disabled: false,
        });
        wallet.account_seq = id + 1;
        self.wallets.update(wallet.clone())?;
        Ok(id)
    }

    pub fn seed_hd(
        &self,
        seed_id: Uuid,
        hd_path: HDPath,
        blockchain: Blockchain,
        password: Option<String>,
        expected_address: Option<Address>,
    ) -> Result<usize, VaultError> {
        let seed = self.seeds.get(seed_id)?;
        let seed = match seed.source {
            SeedSource::Bytes(seed) => {
                if password.is_none() {
                    return Err(VaultError::PasswordRequired);
                }
                seed.decrypt(password.unwrap().as_str())?
            }
            _ => {
                return Err(VaultError::UnsupportedDataError(
                    "No implemented yet".to_string(),
                ))
            }
        };
        let mut wallet = self.wallets.get(self.wallet_id.clone())?;
        let ephemeral_pk = generate_key(&hd_path, seed.as_slice())?;
        let address = ephemeral_pk.to_address();
        if expected_address.is_some() && address != expected_address.unwrap() {
            return Err(VaultError::InvalidDataError(
                "Different address".to_string(),
            ));
        }
        let id = wallet.get_account_id();
        wallet.accounts.push(WalletAccount {
            id,
            blockchain,
            address: Some(address),
            key: PKType::SeedHd(SeedRef {
                seed_id,
                hd_path: StandardHDPath::try_from(hd_path.to_string().as_str()).map_err(|_| {
                    VaultError::ConversionError(ConversionError::InvalidFieldValue("hd_path".to_string()))
                })?,
            }),
            receive_disabled: false,
        });
        wallet.account_seq = id + 1;
        self.wallets.update(wallet.clone())?;
        Ok(id)
    }
}

impl VaultStorage {
    pub fn create<P: AsRef<Path>>(path: P) -> Result<VaultStorage, VaultError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        if !path.is_dir() {
            return Err(VaultError::FilesystemError(
                "Target path is not a dir".to_string(),
            ));
        }
        Ok(VaultStorage {
            dir: path.clone(),
            keys: Arc::new(StandardVaultFiles {
                dir: path.clone(),
                suffix: "key".to_string(),
            }),
            wallets: Arc::new(StandardVaultFiles {
                dir: path.clone(),
                suffix: "wallet".to_string(),
            }),
            seeds: Arc::new(StandardVaultFiles {
                dir: path.clone(),
                suffix: "seed".to_string(),
            }),
        })
    }
}

impl StandardVaultFiles {
    fn get_filename_for(&self, id: Uuid) -> PathBuf {
        let fname = format!("{}.{}", id, self.suffix);
        return self.dir.join(fname);
    }
}

/// Access to Vault storage
pub trait VaultAccess<P>
where
    P: HasUuid,
{
    /// List ids of all items in the storage
    fn list(&self) -> Result<Vec<Uuid>, VaultError>;
    /// Get Item by ID
    fn get(&self, id: Uuid) -> Result<P, VaultError>;
    /// Add a new item
    fn add(&self, entry: P) -> Result<Uuid, VaultError>;
    /// Remove item
    fn remove(&self, id: Uuid) -> Result<bool, VaultError>;
    /// Set the new value of the specified item. The id it taken for entry itself, and used to update the value
    fn update(&self, entry: P) -> Result<bool, VaultError>;

    /// Read all entries in the storage
    fn list_entries(&self) -> Result<Vec<P>, VaultError> {
        let all = self
            .list()?
            .iter()
            .map(|id| self.get(*id))
            .filter(|it| it.is_ok())
            .map(|it| it.unwrap())
            .collect();
        Ok(all)
    }
}

impl<P> VaultAccess<P> for StandardVaultFiles
where
    P: TryFrom<Vec<u8>> + HasUuid,
    Vec<u8>: std::convert::TryFrom<P>,
{
    fn update(&self, entry: P) -> Result<bool, VaultError> {
        let id = entry.get_id();
        let fname = self.get_filename_for(id.clone());
        if fname.exists() {
            let data: Vec<u8> = entry
                .try_into()
                .map_err(|_| ConversionError::InvalidProtobuf)?;
            let archive = Archive::create(&self.dir, ArchiveType::Update);
            let result = safe_update(fname, data.as_slice(), Some(&archive)).map(|_| true);
            archive.finalize();
            result
        } else {
            Err(VaultError::IncorrectIdError)
        }
    }

    fn list(&self) -> Result<Vec<Uuid>, VaultError> {
        let mut result = Vec::new();
        if self.dir.is_dir() {
            for entry in fs::read_dir(&self.dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    match try_vault_file(&path, self.suffix.as_str()) {
                        Ok(id) => {
                            result.push(id);
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        Ok(result)
    }

    fn get(&self, id: Uuid) -> Result<P, VaultError> {
        let f = self.get_filename_for(id.clone());

        let data = fs::read(f)?;
        let pk = P::try_from(data).map_err(|_| ConversionError::InvalidProtobuf)?;
        if !pk.get_id().eq(&id) {
            Err(VaultError::IncorrectIdError)
        } else {
            Ok(pk)
        }
    }

    fn add(&self, entry: P) -> Result<Uuid, VaultError> {
        let id = entry.get_id();
        let f = self.get_filename_for(id.clone());
        if f.exists() {
            return Err(VaultError::FilesystemError("Already exists".to_string()));
        }

        let data: Vec<u8> = entry
            .try_into()
            .map_err(|_| ConversionError::InvalidProtobuf)?;
        //        let data: Vec<u8> = Vec::try_from(pk)?;
        fs::write(f, data.as_slice())?;
        Ok(id)
    }

    fn remove(&self, id: Uuid) -> Result<bool, VaultError> {
        let f = self.get_filename_for(id.clone());
        if !f.exists() {
            return Ok(false);
        }
        if !f.is_file() {
            return Err(VaultError::FilesystemError("Not a file".to_string()));
        }
        let archive = Archive::create(&self.dir, ArchiveType::Delete);
        if archive.submit(f.clone()).is_err() {
            Err(VaultError::FilesystemError(
                "Failed to add to archive".to_string(),
            ))
        } else {
            archive.finalize();
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::read_dir_fully;
    use crate::{
        convert::json::keyfile::EthereumJsonV3File,
        structs::pk::{EthereumPk3, PrivateKeyHolder},
        tests::*,
    };
    use tempdir::TempDir;

    #[test]
    fn try_vault_file_from_standard() {
        let act = try_vault_file(Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.key"), "key");
        assert!(act.is_ok());
        assert_eq!(
            Uuid::from_str("3221aabc-b3ff-4235-829f-9599aba04cb5").unwrap(),
            act.unwrap()
        );
    }

    #[test]
    fn try_vault_file_from_invalid_suffix() {
        let act = try_vault_file(
            Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.seed"),
            "key",
        );
        assert!(act.is_err());
    }

    #[test]
    fn try_vault_file_from_invalid_name() {
        let act = try_vault_file(Path::new("9599aba04cb5.key"), "key");
        assert!(act.is_err());
        let act = try_vault_file(
            Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.key.bak"),
            "key",
        );
        assert!(act.is_err());
        let act = try_vault_file(
            Path::new("~3221aabc-b3ff-4235-829f-9599aba04cb5.key"),
            "key",
        );
        assert!(act.is_err());
        let act = try_vault_file(
            Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.~key"),
            "key",
        );
        assert!(act.is_err());
        let act = try_vault_file(
            Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.key~"),
            "key",
        );
        assert!(act.is_err());
    }

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

    #[test]
    fn creates_seed() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let all = vault.seeds.list().unwrap();
        assert_eq!(0, all.len());

        let seed = Seed::generate(None, "testtest").unwrap();
        let id = seed.get_id();
        let added = vault.seeds.add(seed.clone());
        assert!(added.is_ok());

        let all = vault.seeds.list();
        assert_eq!(vec![id], all.unwrap());
        let seed_act = vault.seeds.get(id).expect("Seed not available");
        assert_eq!(seed, seed_act);
    }

    #[test]
    fn deletes_seed() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed = Seed::generate(None, "testtest").unwrap();
        let id = seed.get_id();
        let added = vault.seeds.add(seed.clone());
        assert!(added.is_ok());

        let all = vault.seeds.list();
        assert_eq!(vec![id], all.unwrap());
        let seed_act = vault.seeds.get(id).expect("Seed not available");
        assert_eq!(seed, seed_act);

        let deleted = vault.seeds.remove(id);
        assert_eq!(deleted, Ok(true));

        let all = vault.seeds.list().unwrap();
        assert_eq!(0, all.len());
    }

    #[test]
    fn uses_different_account_ids() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet::default();
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let wallet = vault.wallets.get(wallet_id.clone()).unwrap();
        assert_eq!(0, wallet.accounts.len());

        let id1 = vault
            .add_account(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let id2 = vault
            .add_account(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::EthereumClassic,
            )
            .unwrap();
        assert_ne!(id1, id2);

        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(2, wallet.accounts.len());
        assert_eq!(id1, wallet.accounts[0].id);
        assert_eq!(id2, wallet.accounts[1].id);

        //not necessary, but true for the current implementation
        assert_eq!(id1 + 1, id2);
        assert_eq!(0, id1);
        assert_eq!(1, id2);
    }

    #[test]
    fn start_account_id_from_seq() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            account_seq: 1015,
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_account(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(1015, id1);
        let wallet = vault.wallets.get(wallet_id).unwrap();

        assert_eq!(1016, wallet.account_seq);
        assert_eq!(1015, wallet.accounts[0].id);
    }

    #[test]
    fn doesnt_reuse_account_id() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet::default();
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let wallet = vault.wallets.get(wallet_id.clone()).unwrap();
        assert_eq!(0, wallet.accounts.len());

        let id1 = vault
            .add_account(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let id2 = vault
            .add_account(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::EthereumClassic,
            )
            .unwrap();

        let mut wallet = vault.wallets.get(wallet_id).unwrap();

        wallet.accounts.remove(1);
        vault.wallets.update(wallet).expect("Not saved");

        let id3 = vault
            .add_account(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::EthereumClassic,
            )
            .unwrap();

        assert_ne!(id2, id3);

        let wallet = vault.wallets.get(wallet_id).unwrap();

        assert_eq!(2, wallet.accounts.len());
        assert_eq!(id1, wallet.accounts[0].id);
        assert_eq!(id3, wallet.accounts[1].id);

        //not necessary, but true for the current implementation
        assert_eq!(id1 + 1, id2);
        assert_eq!(id2 + 1, id3);
        assert_eq!(0, id1);
        assert_eq!(1, id2);
        assert_eq!(2, id3);
    }

    #[test]
    fn safe_update_ok() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();
        let f = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key");
        fs::write(&f, "test 1").unwrap();
        assert_eq!(fs::read_dir(&tmp_dir).unwrap().count(), 1);
        let result = safe_update(&f, "test 2", None);
        assert!(result.is_ok());
        assert_eq!(fs::read_dir(&tmp_dir).unwrap().count(), 1);
        let act = fs::read_to_string(&f).unwrap();
        assert_eq!(act, "test 2")
    }

    #[test]
    fn safe_update_when_bak_exists() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();
        let f = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key");
        fs::write(&f, "test 1").unwrap();

        let f_bak = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key.bak");
        fs::write(&f_bak, "test 2").unwrap();

        assert_eq!(fs::read_dir(&tmp_dir).unwrap().count(), 2);

        let result = safe_update(&f, "test 3", None);
        assert!(result.is_err());

        assert_eq!(fs::read_dir(&tmp_dir).unwrap().count(), 2);
        let act = fs::read_to_string(&f).unwrap();
        assert_eq!(act, "test 1")
    }

    #[test]
    fn safe_update_copies_to_archive() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();
        let archive = Archive::create(tmp_dir.clone(), ArchiveType::Other);
        let f = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key");
        fs::write(&f, "test 1").unwrap();
        let result = safe_update(&f, "test 2", Some(&archive));
        assert!(result.is_ok());

        let arch_dir = get_archived(tmp_dir.clone()).unwrap();
        println!("Archive: {:?}", arch_dir.clone());
        let archive_copy = arch_dir.join("e779c975-6791-47a3-a4d6-d0e976d02820.key.bak");
        assert!(archive_copy.exists());
        assert_eq!(fs::read_to_string(archive_copy).unwrap(), "test 1");
    }

    #[test]
    fn safe_update_deletes_if_archive_full() {
        // init_tests();

        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();
        let archive = Archive::create(tmp_dir.clone(), ArchiveType::Other);
        archive.write(
            "e779c975-6791-47a3-a4d6-d0e976d02820.key.bak",
            "test old backup",
        ).unwrap();

        let f = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key");
        fs::write(&f, "test orig").unwrap();
        let result = safe_update(&f, "test updated", Some(&archive));
        assert!(result.is_ok());
        let act = fs::read_to_string(&f).unwrap();
        assert_eq!(act, "test updated");

        let arch_dir = get_archived(tmp_dir.clone()).unwrap();
        let archive_copy = arch_dir.join("e779c975-6791-47a3-a4d6-d0e976d02820.key.bak");
        assert!(archive_copy.exists());
        assert_eq!(fs::read_to_string(archive_copy).unwrap(), "test old backup");

        let in_vault = read_dir_fully(tmp_dir.clone())
            .iter()
            .filter(|x| x.path().is_file())
            .count();
        assert_eq!(in_vault, 1);
    }

    #[test]
    fn removes_to_archive() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();
        let f = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key");
        fs::write(&f, "test 1").unwrap();
        let vault = VaultStorage::create(tmp_dir.clone()).unwrap();
        let removed = vault
            .keys()
            .remove(Uuid::from_str("e779c975-6791-47a3-a4d6-d0e976d02820").unwrap());

        assert_eq!(removed, Ok(true));

        let arch_dir = get_archived(tmp_dir.clone()).unwrap();
        let archive_copy = arch_dir.join("e779c975-6791-47a3-a4d6-d0e976d02820.key");
        assert!(archive_copy.exists());
        assert_eq!(fs::read_to_string(archive_copy).unwrap(), "test 1");

        assert!(!f.exists());
        let in_vault = read_dir_fully(tmp_dir.clone())
            .iter()
            .filter(|x| x.path().is_file())
            .count();
        assert_eq!(in_vault, 0);
    }

    #[test]
    fn skip_restore_if_ok() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();
        let f = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key");
        fs::write(&f, "test 1").unwrap();
        let vault = VaultStorage::create(tmp_dir.clone()).unwrap();

        let act = vault.revert_backups();
        assert_eq!(act, Ok(0));

        assert!(f.exists());
    }

    #[test]
    fn restores_backup() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();
        let f = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key.bak");
        fs::write(&f, "test 1").unwrap();
        let vault = VaultStorage::create(tmp_dir.clone()).unwrap();

        let act = vault.revert_backups();
        assert_eq!(act, Ok(1));

        assert!(!f.exists());

        let f_orig = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key");
        assert!(f_orig.exists());
        assert_eq!(fs::read_to_string(f_orig).unwrap(), "test 1");
    }

    #[test]
    fn archive_stale_backup() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();
        let f_bak = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key.bak");
        let f_orig = tmp_dir
            .clone()
            .join("e779c975-6791-47a3-a4d6-d0e976d02820.key");
        fs::write(&f_bak, "test 1").unwrap();
        fs::write(&f_orig, "test 2").unwrap();

        let vault = VaultStorage::create(tmp_dir.clone()).unwrap();

        let act = vault.revert_backups();
        assert_eq!(act, Ok(1));

        assert!(f_orig.exists());
        assert_eq!(fs::read_to_string(f_orig).unwrap(), "test 2");
        assert!(!f_bak.exists());

        let arch_dir = get_archived(tmp_dir.clone()).unwrap();

        let f_archived = arch_dir.join("e779c975-6791-47a3-a4d6-d0e976d02820.key.bak");
        assert!(f_archived.exists());
        assert_eq!(fs::read_to_string(f_archived).unwrap(), "test 1");
    }
}
