use crate::{
    chains::Blockchain,
    convert::{error::ConversionError, json::keyfile::EthereumJsonV3File},
    storage::{
        addressbook::AddressbookStorage,
        archive::{Archive, ArchiveType},
        snapshot::Snapshots,
        global_key::VaultGlobalKey
    },
    error::VaultError,
    structs::{
        book::AddressRef,
        pk::PrivateKeyHolder,
        seed::Seed,
        types::HasUuid,
        wallet::{PKType, Wallet, WalletEntry},
    },
};
use regex::Regex;
use std::{
    convert::{TryFrom, TryInto},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use std::ffi::OsStr;
use std::sync::mpsc::Receiver;
use std::sync::Mutex;
use uuid::Uuid;
use crate::storage::files::try_vault_file;
use crate::storage::icons::Icons;
use crate::storage::vault_ethereum::AddEthereumEntry;
use crate::storage::vault_bitcoin::AddBitcoinEntry;
use crate::storage::watch::{Watch, Request, Event};
use crate::structs::crypto::GlobalKey;

/// Compound trait for a vault entry which is stored in a separate file each
pub trait VaultAccessByFile<P>: VaultAccess<P> + SingleFileEntry
    where
        P: HasUuid + Ord,
{}

#[derive(Clone)]
pub struct VaultStorage {
    pub dir: PathBuf,
    watch: Arc<Mutex<Watch>>,

    keys: Arc<dyn VaultAccessByFile<PrivateKeyHolder>>,
    wallets: Arc<dyn VaultAccessByFile<Wallet>>,
    seeds: Arc<dyn VaultAccessByFile<Seed>>,
}

#[derive(Clone)]
struct StandardVaultFiles {
    dir: PathBuf,
    suffix: String,
}

/// Main interface to the Emerald Vault storage
impl VaultStorage {

    ///
    /// Check if the extension (`ext`) is used by the vault main files
    pub fn is_vault_ext(ext: &OsStr) -> bool {
        ext == "key" || ext == "wallet" || ext == "seed" || ext == "bak" || ext == "icon"
    }

    pub fn icons(&self) -> Icons {
        Icons {
            dir: self.dir.clone()
        }
    }
    pub fn keys(&self) -> Arc<dyn VaultAccessByFile<PrivateKeyHolder>> {
        self.keys.clone()
    }
    pub fn wallets(&self) -> Arc<dyn VaultAccessByFile<Wallet>> {
        self.wallets.clone()
    }
    pub fn seeds(&self) -> Arc<dyn VaultAccessByFile<Seed>> {
        self.seeds.clone()
    }
    pub fn create_new(&self) -> CreateWallet {
        CreateWallet {
            storage: Arc::new(self.clone()),
            keys: self.keys(),
            wallets: self.wallets(),
            seeds: self.seeds(),
            global: self.global_key().get_if_exists().unwrap(),
        }
    }
    pub fn addressbook(&self) -> AddressbookStorage {
        AddressbookStorage::from_path(self.dir.clone().join("addressbook.csv"))
    }
    pub fn global_key(&self) -> VaultGlobalKey {
        let dir = &self.dir;
        VaultGlobalKey { vault: dir.clone() }
    }

    ///
    /// Manage snapshots for the current Vault
    pub fn snapshots(&self) -> Snapshots {
        Snapshots::open(self)
    }

    pub fn add_ethereum_entry(&self, wallet_id: Uuid) -> AddEthereumEntry {
        AddEthereumEntry::new(
            &wallet_id,
            self.keys.clone(),
            self.seeds.clone(),
            self.wallets.clone(),
            self.global_key().get_if_exists().unwrap(),
        )
    }

    pub fn add_bitcoin_entry(&self, wallet_id: Uuid) -> AddBitcoinEntry {
        AddBitcoinEntry::new(
            &wallet_id,
            self.seeds.clone(),
            self.wallets.clone(),
            self.global_key().get_if_exists().unwrap(),
        )
    }

    ///Access to functions for updating the entry
    pub fn update_entry(&self, wallet_id: Uuid, entry_id: usize) -> UpdateEntry {
        UpdateEntry {
            wallets: self.wallets().clone(),
            wallet_id,
            entry_id,
        }
    }

    ///Remove entry from a wallet.
    ///Returns Ok(true) if entry was found and removed, Ok(false) if entry wasn't found, and Err if an error happened
    pub fn remove_entry(&self, wallet_id: Uuid, entry_id: usize) -> Result<bool, VaultError> {
        let mut wallet = self.wallets().get(wallet_id)?;
        let pos = wallet.entries.iter().position(|e| e.id == entry_id);
        match pos {
            Some(pos) => {
                let entry = wallet.entries.remove(pos);
                let updated = self.wallets.update(wallet)?;
                match entry.key {
                    PKType::PrivateKeyRef(uuid) => {
                        //check all other wallets, to make sure it's not referenced from another entry
                        let used = &self
                            .wallets
                            .list_entries()?
                            .iter()
                            .filter(|w| w.id != wallet_id)
                            .any(|w| {
                                w.entries.iter().any(|e| match e.key {
                                    PKType::PrivateKeyRef(x) => x == uuid,
                                    _ => false,
                                })
                            });
                        if !used {
                            self.keys.remove(uuid)?;
                        }
                    }
                    PKType::SeedHd(_) => {}
                }
                Ok(updated)
            }
            None => Ok(false),
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

    /// Get all files related to the wallet. I.e. raw private keys
    ///
    /// # Arguments
    ///
    /// * `wallet_id` - id of the wallet
    /// * `exclusive_only` - true if should return only filenames that are _NOT_ used by any other wallet
    pub fn get_wallet_files(
        &self,
        wallet_id: Uuid,
        exclusive_only: bool,
    ) -> Result<Vec<PathBuf>, VaultError> {
        // helper to get uuids of all individual private keys for a wallet
        let fn_wallet_entries = |w: &Wallet| {
            w.entries
                .iter()
                .filter_map(|acc| match acc.key {
                    PKType::PrivateKeyRef(pk_id) => Some(pk_id),
                    PKType::SeedHd(_) => None,
                })
                .collect::<Vec<Uuid>>()
        };

        let other_wallets: Vec<Wallet> = self
            .wallets
            .list()?
            .iter()
            .filter(|id| id.clone().ne(&wallet_id))
            .map(|id| self.wallets.get(id.clone()))
            .filter_map(|r| r.ok())
            .collect();

        // uuids of all other private keys in the vault
        // TODO need to do only if exclusive_only=true
        let other_wallet_pks = other_wallets
            .iter()
            .flat_map(fn_wallet_entries)
            .collect::<Vec<Uuid>>();

        if let Ok(wallet) = self.wallets.get(wallet_id) {
            let pks: Vec<Uuid> = fn_wallet_entries(&wallet)
                .iter()
                .filter(|pk_id| !exclusive_only || !other_wallet_pks.contains(pk_id))
                .map(|r| r.clone())
                .collect();
            let mut files = pks
                .iter()
                .map(|pk| self.keys.get_filename_for(pk.clone()))
                .collect::<Vec<PathBuf>>();

            files.push(self.wallets.get_filename_for(wallet_id));
            return Ok(files);
        }
        return Ok(vec![]);
    }

    /// Removes a wallet with all related private keys exclusively used by that wallet. Seeds are
    /// kept untouched.
    pub fn remove_wallet(&self, id: Uuid) -> Result<bool, VaultError> {
        let all = self.get_wallet_files(id, true)?;
        if all.is_empty() {
            return Ok(false);
        }
        let len = all.len();
        let archive = Archive::create(&self.dir, ArchiveType::Delete);
        let mut errors = 0;
        for f in all {
            if archive.submit(f.clone()).is_err() {
                errors += 1;
            }
        }
        if errors == len {
            return Err(VaultError::FilesystemError(
                "Failed to add to archive".to_string(),
            ));
        }
        archive.finalize();
        Ok(errors == 0)
    }

    // Watch avaialbility of a HW key
    pub fn watch(&self, request: Request) -> Receiver<Event> {
        let mut watch = self.watch.lock().unwrap();
        (*watch).request(request)
    }
}

/// Safe update of a file, with making a .bak copy of the existing file, writing new content and
/// only then removing initial data. If it fails at some point, or backup is already exists, it
/// returns error
pub(crate) fn safe_update<P: AsRef<Path>, C: AsRef<[u8]>>(
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

pub struct CreateWallet {
    storage: Arc<VaultStorage>,
    keys: Arc<dyn VaultAccessByFile<PrivateKeyHolder>>,
    wallets: Arc<dyn VaultAccessByFile<Wallet>>,
    #[allow(dead_code)]
    seeds: Arc<dyn VaultAccessByFile<Seed>>,
    global: Option<GlobalKey>,
}

impl CreateWallet {

    ///Create a new Wallet with the the specified Private Key. All fields for the wallet are set
    ///with default or empty values.
    ///
    ///Returns UUID of the newly created wallet
    pub fn raw_pk(
        &self,
        pk: Vec<u8>,
        password: &str,
        blockchain: Blockchain,
    ) -> Result<Uuid, VaultError> {
        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = self.wallets.add(wallet)?;
        let _ = self.storage
            .add_ethereum_entry(wallet_id)
            .raw_pk(pk, password, blockchain)?;
        Ok(wallet_id)
    }

    ///Create a new Wallet with the the specified Ethereum JSON Private Key. All fields for the wallet are set
    ///with default or empty values. The labels is set from JSON name field, if available.
    ///
    ///Returns UUID of the newly created wallet
    pub fn ethereum(
        &self,
        json: &EthereumJsonV3File,
        json_password: &str,
        blockchain: Blockchain,
        global_password: &str
    ) -> Result<Uuid, VaultError> {
        let wallet = Wallet {
            label: json.name.clone(),
            ..Wallet::default()
        };
        let wallet_id = self.wallets.add(wallet)?;

        let _ = self.storage
            .add_ethereum_entry(wallet_id)
            .json(json, json_password, blockchain, global_password)?;

        Ok(wallet_id)
    }
}

pub struct UpdateEntry {
    wallets: Arc<dyn VaultAccessByFile<Wallet>>,
    wallet_id: Uuid,
    entry_id: usize,
}

impl UpdateEntry {
    fn get_wallet(&self) -> Result<Wallet, VaultError> {
        self.wallets.get(self.wallet_id)
    }

    fn update<F>(&self, mut f: F) -> Result<bool, VaultError>
    where
        F: FnMut(&mut WalletEntry) -> (),
    {
        let mut wallet = self.get_wallet()?;
        let pos = wallet.entries.iter().position(|e| e.id == self.entry_id);
        match pos {
            Some(pos) => {
                let mut entry = wallet.entries[pos].clone();
                f(&mut entry);
                wallet.entries[pos] = entry;
                let updated = self.wallets.update(wallet)?;
                Ok(updated)
            }
            None => Ok(false),
        }
    }

    ///Update (set value or set none) of a label for the wallet entry
    pub fn set_label(&self, label: Option<String>) -> Result<bool, VaultError> {
        self.update(|e| e.label = label.clone())
    }

    ///Enable ot disable receiving flag for the entry
    pub fn set_receive_disabled(&self, disabled: bool) -> Result<bool, VaultError> {
        self.update(|e| e.receive_disabled = disabled)
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
            // I know. Just don't look at it.
            watch: Arc::new(Mutex::new(Watch::new(Arc::new(Mutex::new(StandardVaultFiles {
                dir: path.clone(),
                suffix: "seed".to_string(),
            }))))),
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

/// For entries that are stored in a single separate file
pub trait SingleFileEntry {
    /// Get full filename for the entry by id
    fn get_filename_for(&self, id: Uuid) -> PathBuf;
}

impl SingleFileEntry for StandardVaultFiles {
    /// Filename for entry id
    fn get_filename_for(&self, id: Uuid) -> PathBuf {
        let fname = format!("{}.{}", id, self.suffix);
        return self.dir.join(fname);
    }
}

impl<P> VaultAccessByFile<P> for StandardVaultFiles
    where
        P: TryFrom<Vec<u8>> + HasUuid + Ord,
        Vec<u8>: std::convert::TryFrom<P>,
{
}

/// Access to Vault storage
pub trait VaultAccess<P>
    where
        P: HasUuid + Ord,
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
    /// Multiple updates, all backed up to the same archive
    fn update_multiple(&self, entry: P, archive: &Archive) -> Result<bool, VaultError>;

    /// Read all entries in the storage
    fn list_entries(&self) -> Result<Vec<P>, VaultError> {
        let mut all: Vec<P> = self
            .list()?
            .iter()
            .map(|id| self.get(*id))
            .filter(|it| it.is_ok())
            .map(|it| it.unwrap())
            .collect();
        all.sort();
        Ok(all)
    }
}

impl<P> VaultAccess<P> for StandardVaultFiles
    where
        P: TryFrom<Vec<u8>> + HasUuid + Ord,
        Vec<u8>: std::convert::TryFrom<P>,
{
    fn update(&self, entry: P) -> Result<bool, VaultError> {
        let archive = Archive::create(&self.dir, ArchiveType::Update);
        let result = self.update_multiple(entry, &archive);
        archive.finalize();
        return result
    }

    fn update_multiple(&self, entry: P, archive: &Archive) -> Result<bool, VaultError> {
        let id = entry.get_id();
        let fname = self.get_filename_for(id.clone());
        if fname.exists() {
            let data: Vec<u8> = entry
                .try_into()
                .map_err(|_| ConversionError::InvalidProtobuf)?;
            let result = safe_update(fname, data.as_slice(), Some(&archive)).map(|_| true);
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
        result.sort();
        Ok(result)
    }

    fn get(&self, id: Uuid) -> Result<P, VaultError> {
        let f = self.get_filename_for(id.clone());

        let data = fs::read(f)?;
        let entry = P::try_from(data).map_err(|_| ConversionError::InvalidProtobuf)?;
        if !entry.get_id().eq(&id) {
            Err(VaultError::IncorrectIdError)
        } else {
            Ok(entry)
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
    use crate::{
        tests::{read_dir_fully, *},
    };
    use chrono::{TimeZone, Utc};
    use tempdir::TempDir;
    use std::str::FromStr;

    #[test]
    fn creates_seed() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let all = vault.seeds.list().unwrap();
        assert_eq!(0, all.len());

        let mut seed = Seed::test_generate(None, "testtest".as_bytes(), None).unwrap();
        seed.created_at = Utc.timestamp_millis(0);
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

        let mut seed = Seed::test_generate(None, "testtest".as_bytes(), None).unwrap();
        seed.created_at = Utc.timestamp_millis(0);
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
    fn order_seeds_by_date_and_id() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let mut seed = Seed::test_generate(None, "testtest".as_bytes(), None).unwrap();
        seed.id = Uuid::parse_str("13052693-c51c-4e8b-91b3-564d3cb78fb4").unwrap();
        // 2 jan 2020
        seed.created_at = Utc.timestamp_millis(1577962800000);
        vault.seeds.add(seed.clone()).unwrap();

        let mut seed = Seed::test_generate(None, "testtest".as_bytes(), None).unwrap();
        seed.id = Uuid::parse_str("5e47360d-3dc2-4b39-b399-75fbdd4ac020").unwrap();
        seed.created_at = Utc.timestamp_millis(0);
        vault.seeds.add(seed.clone()).unwrap();

        let mut seed = Seed::test_generate(None, "testtest".as_bytes(), None).unwrap();
        seed.id = Uuid::parse_str("36805dff-a6e0-434d-be7d-5ef7931522d0").unwrap();
        // 1 jan 2020
        seed.created_at = Utc.timestamp_millis(1577876400000);
        vault.seeds.add(seed.clone()).unwrap();

        let mut seed = Seed::test_generate(None, "testtest".as_bytes(), None).unwrap();
        seed.id = Uuid::parse_str("067e14c4-85de-421e-9957-48a1cdef42ae").unwrap();
        seed.created_at = Utc.timestamp_millis(0);
        vault.seeds.add(seed.clone()).unwrap();

        //first comes items without date
        //#4 -> #2
        //then ordered date
        //#3 -> #1

        let seeds = vault.seeds.list_entries().unwrap();
        assert_eq!(
            seeds.get(0).unwrap().id.to_string(),
            "067e14c4-85de-421e-9957-48a1cdef42ae".to_string()
        );
        assert_eq!(
            seeds.get(1).unwrap().id.to_string(),
            "5e47360d-3dc2-4b39-b399-75fbdd4ac020".to_string()
        );
        assert_eq!(
            seeds.get(2).unwrap().id.to_string(),
            "36805dff-a6e0-434d-be7d-5ef7931522d0".to_string()
        );
        assert_eq!(
            seeds.get(3).unwrap().id.to_string(),
            "13052693-c51c-4e8b-91b3-564d3cb78fb4".to_string()
        );
    }

    #[test]
    fn order_wallets_by_date_and_id() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        vault
            .wallets
            .add(Wallet {
                id: Uuid::parse_str("13052693-c51c-4e8b-91b3-564d3cb78fb4").unwrap(),
                // 2 jan 2020
                created_at: Utc.timestamp_millis(1577962800000),
                ..Wallet::default()
            })
            .unwrap();
        vault
            .wallets
            .add(Wallet {
                id: Uuid::parse_str("5e47360d-3dc2-4b39-b399-75fbdd4ac020").unwrap(),
                created_at: Utc.timestamp_millis(0),
                ..Wallet::default()
            })
            .unwrap();
        vault
            .wallets
            .add(Wallet {
                id: Uuid::parse_str("36805dff-a6e0-434d-be7d-5ef7931522d0").unwrap(),
                // 1 jan 2020
                created_at: Utc.timestamp_millis(1577876400000),
                ..Wallet::default()
            })
            .unwrap();
        vault
            .wallets
            .add(Wallet {
                id: Uuid::parse_str("067e14c4-85de-421e-9957-48a1cdef42ae").unwrap(),
                created_at: Utc.timestamp_millis(0),
                ..Wallet::default()
            })
            .unwrap();

        //first comes items without date
        //#4 -> #2
        //then ordered date
        //#3 -> #1

        let seeds = vault.wallets.list_entries().unwrap();
        assert_eq!(
            seeds.get(0).unwrap().id.to_string(),
            "067e14c4-85de-421e-9957-48a1cdef42ae".to_string()
        );
        assert_eq!(
            seeds.get(1).unwrap().id.to_string(),
            "5e47360d-3dc2-4b39-b399-75fbdd4ac020".to_string()
        );
        assert_eq!(
            seeds.get(2).unwrap().id.to_string(),
            "36805dff-a6e0-434d-be7d-5ef7931522d0".to_string()
        );
        assert_eq!(
            seeds.get(3).unwrap().id.to_string(),
            "13052693-c51c-4e8b-91b3-564d3cb78fb4".to_string()
        );
    }

    #[test]
    fn uses_different_entry_ids() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet::default();
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let wallet = vault.wallets.get(wallet_id.clone()).unwrap();
        assert_eq!(0, wallet.entries.len());

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let id2 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::EthereumClassic,
            )
            .unwrap();
        assert_ne!(id1, id2);

        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(2, wallet.entries.len());
        assert_eq!(id1, wallet.entries[0].id);
        assert_eq!(id2, wallet.entries[1].id);

        //not necessary, but true for the current implementation
        assert_eq!(id1 + 1, id2);
        assert_eq!(0, id1);
        assert_eq!(1, id2);
    }

    #[test]
    fn start_entry_id_from_seq() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            entry_seq: 1015,
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(1015, id1);
        let wallet = vault.wallets.get(wallet_id).unwrap();

        assert_eq!(1016, wallet.entry_seq);
        assert_eq!(1015, wallet.entries[0].id);
    }

    #[test]
    fn doesnt_reuse_entry_id() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet::default();
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let wallet = vault.wallets.get(wallet_id.clone()).unwrap();
        assert_eq!(0, wallet.entries.len());

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let id2 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::EthereumClassic,
            )
            .unwrap();

        let mut wallet = vault.wallets.get(wallet_id).unwrap();

        wallet.entries.remove(1);
        vault.wallets.update(wallet).expect("Not saved");

        let id3 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::EthereumClassic,
            )
            .unwrap();

        assert_ne!(id2, id3);

        let wallet = vault.wallets.get(wallet_id).unwrap();

        assert_eq!(2, wallet.entries.len());
        assert_eq!(id1, wallet.entries[0].id);
        assert_eq!(id3, wallet.entries[1].id);

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
        archive
            .write(
                "e779c975-6791-47a3-a4d6-d0e976d02820.key.bak",
                "test old backup",
            )
            .unwrap();

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

    #[test]
    fn delete_wallet_with_pk() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();

        let vault = VaultStorage::create(tmp_dir).unwrap();
        let wallet_id = vault
            .create_new()
            .raw_pk(
                EthereumPrivateKey::gen().to_vec(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let wallet = vault.wallets.get(wallet_id).unwrap();
        let pk_id = match wallet.entries.first().unwrap().key {
            PKType::PrivateKeyRef(id) => id,
            _ => panic!("not PrivateKey Ref"),
        };
        let pk = vault.keys.get(pk_id);
        assert!(pk.is_ok());

        let deleted = vault.remove_wallet(wallet_id);
        assert_eq!(Ok(true), deleted);

        let wallet = vault.wallets.get(wallet_id);
        assert!(wallet.is_err());
        let pk = vault.keys.get(pk_id);
        assert!(pk.is_err());
    }

    #[test]
    fn delete_wallet_with_pk_keeps_others() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();

        let vault = VaultStorage::create(tmp_dir).unwrap();
        let wallet_1_id = vault
            .create_new()
            .raw_pk(
                EthereumPrivateKey::gen().to_vec(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let wallet_1 = vault.wallets.get(wallet_1_id).unwrap();
        let pk_id_1 = match wallet_1.entries.first().unwrap().key {
            PKType::PrivateKeyRef(id) => id,
            _ => panic!("not PrivateKey Ref"),
        };

        let wallet_2_id = vault
            .create_new()
            .raw_pk(
                EthereumPrivateKey::gen().to_vec(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let wallet_2 = vault.wallets.get(wallet_2_id).unwrap();
        let pk_id_2 = match wallet_2.entries.first().unwrap().key {
            PKType::PrivateKeyRef(id) => id,
            _ => panic!("not PrivateKey Ref"),
        };

        let pk = vault.keys.get(pk_id_1);
        assert!(pk.is_ok());

        let deleted = vault.remove_wallet(wallet_1_id);
        assert_eq!(Ok(true), deleted);

        let wallet = vault.wallets.get(wallet_1_id);
        assert!(wallet.is_err());
        let pk = vault.keys.get(pk_id_1);
        assert!(pk.is_err());

        let wallet = vault.wallets.get(wallet_2_id);
        assert!(wallet.is_ok());
        assert_eq!(wallet.unwrap().id, wallet_2_id);
        let pk = vault.keys.get(pk_id_2);
        assert!(pk.is_ok());
        assert_eq!(pk.unwrap().id, pk_id_2);
    }

    #[test]
    fn delete_wallet_with_pk_keeps_used_twice() {
        let tmp_dir = TempDir::new("emerald-vault-test")
            .expect("Dir not created")
            .into_path();

        let vault = VaultStorage::create(tmp_dir).unwrap();
        let wallet_1_id = vault
            .create_new()
            .raw_pk(
                EthereumPrivateKey::gen().to_vec(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let wallet_1 = vault.wallets.get(wallet_1_id).unwrap();
        let pk_id_1 = match wallet_1.entries.first().unwrap().key {
            PKType::PrivateKeyRef(id) => id,
            _ => panic!("not PrivateKey Ref"),
        };

        let wallet_2_id = vault
            .create_new()
            .raw_pk(
                EthereumPrivateKey::gen().to_vec(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let mut wallet_2 = vault.wallets.get(wallet_2_id).unwrap();
        let pk_id_2 = match wallet_2.entries.first().unwrap().key {
            PKType::PrivateKeyRef(id) => id,
            _ => panic!("not PrivateKey Ref"),
        };
        wallet_2.entries.push(WalletEntry {
            id: 2,
            blockchain: Blockchain::Ethereum,
            address: None,
            key: PKType::PrivateKeyRef(pk_id_1),
            ..WalletEntry::default()
        });
        vault.wallets.update(wallet_2).expect("not updated");

        let pk = vault.keys.get(pk_id_1);
        assert!(pk.is_ok());

        let deleted = vault.remove_wallet(wallet_1_id);
        assert_eq!(Ok(true), deleted);

        let wallet = vault.wallets.get(wallet_1_id);
        assert!(wallet.is_err());

        let pk = vault.keys.get(pk_id_1);
        //not deleted because used by both wallet_1 and wallet_2
        assert!(pk.is_ok());

        let wallet = vault.wallets.get(wallet_2_id);
        assert!(wallet.is_ok());
        let wallet = wallet.unwrap();
        assert_eq!(wallet.id, wallet_2_id);
        assert_eq!(wallet.entries.len(), 2);
        let pk = vault.keys.get(pk_id_2);
        assert!(pk.is_ok());
        assert_eq!(pk.unwrap().id, pk_id_2);
    }

    #[test]
    fn remove_single_entry() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);

        //make sure it actually exists
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(id1, wallet.entries[0].id);

        let removed = vault.remove_entry(wallet_id, id1);
        assert_eq!(Ok(true), removed);

        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(0, wallet.entries.len());
    }

    #[test]
    fn remove_first_entry() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("a69e8bbb5cc24229e20d8766fd298291bba6bdfac192ceb5fd772906bea3e118")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(1, id2);

        //make sure it actually exists
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(2, wallet.entries.len());
        assert_eq!(id1, wallet.entries[0].id);
        assert_eq!(id2, wallet.entries[1].id);

        let removed = vault.remove_entry(wallet_id, id1);
        assert_eq!(Ok(true), removed);

        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(1, wallet.entries.len());
        assert_eq!(id2, wallet.entries[0].id);
    }

    #[test]
    fn remove_second_entry() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("69e8bbb5cc24229e20d8766fd298291bba6bdfac192ceb5fd772906bea3e118a")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(1, id2);

        //make sure it actually exists
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(2, wallet.entries.len());
        assert_eq!(id1, wallet.entries[0].id);
        assert_eq!(id2, wallet.entries[1].id);
        assert_eq!(2, wallet.entry_seq);

        let removed = vault.remove_entry(wallet_id, id2);
        assert_eq!(Ok(true), removed);

        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(1, wallet.entries.len());
        assert_eq!(id1, wallet.entries[0].id);
        assert_eq!(2, wallet.entry_seq);
    }

    #[test]
    fn remove_non_existing_entry() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("9e8bbb5cc24229e20d8766fd298291bba6bdfac192ceb5fd772906bea3e118a6")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(1, id2);

        //make sure it actually exists
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(2, wallet.entries.len());
        assert_eq!(id1, wallet.entries[0].id);
        assert_eq!(id2, wallet.entries[1].id);
        assert_eq!(2, wallet.entry_seq);

        let removed = vault.remove_entry(wallet_id, 10);
        assert_eq!(Ok(false), removed);

        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(2, wallet.entries.len());
        assert_eq!(id1, wallet.entries[0].id);
        assert_eq!(id2, wallet.entries[1].id);
        assert_eq!(2, wallet.entry_seq);
    }

    #[test]
    fn set_entry_label() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();

        //make sure there is no label
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(None, wallet.entries[0].label);

        let result = vault
            .update_entry(wallet_id, id1)
            .set_label(Some("New Label".to_string()));
        assert_eq!(Ok(true), result);
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(Some("New Label".to_string()), wallet.entries[0].label);

        let result = vault
            .update_entry(wallet_id, id1)
            .set_label(Some("New Label 2".to_string()));
        assert_eq!(Ok(true), result);
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(Some("New Label 2".to_string()), wallet.entries[0].label);

        let result = vault.update_entry(wallet_id, id1).set_label(None);
        assert_eq!(Ok(true), result);
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(None, wallet.entries[0].label);
    }

    #[test]
    fn doesnt_set_entry_label_for_no_entry() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);

        let result = vault
            .update_entry(wallet_id, 5)
            .set_label(Some("x".to_string()));
        assert_eq!(Ok(false), result);
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(None, wallet.entries[0].label);
    }

    #[test]
    fn set_entry_receive_flag() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();

        let result = vault
            .update_entry(wallet_id, id1)
            .set_receive_disabled(true);
        assert_eq!(Ok(true), result);
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(true, wallet.entries[0].receive_disabled);

        let result = vault
            .update_entry(wallet_id, id1)
            .set_receive_disabled(false);
        assert_eq!(Ok(true), result);
        let wallet = vault.wallets.get(wallet_id).unwrap();
        assert_eq!(false, wallet.entries[0].receive_disabled);
    }

    #[test]
    fn removing_entry_removes_pk() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("bb5cc24229e20d8766fd298291bba6bdfac192ceb5fd772906bea3e118a69e8b")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(1, id2);

        //make sure it actually exists
        let wallet = vault.wallets.get(wallet_id).unwrap();

        let pk1 = match wallet.entries[0].key {
            PKType::PrivateKeyRef(uuid) => uuid,
            _ => panic!("invalid pk"),
        };
        let pk2 = match wallet.entries[1].key {
            PKType::PrivateKeyRef(uuid) => uuid,
            _ => panic!("invalid pk"),
        };

        Path::new(tmp_dir.path());
        assert!(Path::new(tmp_dir.path())
            .join(format!("{}.key", pk1.to_string()))
            .exists());
        assert!(Path::new(tmp_dir.path())
            .join(format!("{}.key", pk2.to_string()))
            .exists());

        let removed = vault.remove_entry(wallet_id, id1);
        assert_eq!(Ok(true), removed);

        assert!(!Path::new(tmp_dir.path())
            .join(format!("{}.key", pk1.to_string()))
            .exists());
        assert!(Path::new(tmp_dir.path())
            .join(format!("{}.key", pk2.to_string()))
            .exists());
    }

    #[test]
    fn removing_entry_keeps_pk_used_by_another_wallet() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets.add(wallet).unwrap();

        let id1 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_ethereum_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("9e8bbb5cc24229e20d8766fd298291bba6bdfac192ceb5fd772906bea3e118a6")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(1, id2);

        //make sure it actually exists
        let wallet = vault.wallets.get(wallet_id).unwrap();

        let pk1 = match wallet.entries[0].key {
            PKType::PrivateKeyRef(uuid) => uuid,
            _ => panic!("invalid pk"),
        };
        let pk2 = match wallet.entries[1].key {
            PKType::PrivateKeyRef(uuid) => uuid,
            _ => panic!("invalid pk"),
        };

        Path::new(tmp_dir.path());
        assert!(Path::new(tmp_dir.path())
            .join(format!("{}.key", pk1.to_string()))
            .exists());
        assert!(Path::new(tmp_dir.path())
            .join(format!("{}.key", pk2.to_string()))
            .exists());

        let mut copy = wallet.clone();
        copy.id = Uuid::new_v4();

        vault.wallets().add(copy).expect("not added");

        let removed = vault.remove_entry(wallet_id, id1);
        assert_eq!(Ok(true), removed);

        assert!(Path::new(tmp_dir.path())
            .join(format!("{}.key", pk1.to_string()))
            .exists());
        assert!(Path::new(tmp_dir.path())
            .join(format!("{}.key", pk2.to_string()))
            .exists());
    }
}
