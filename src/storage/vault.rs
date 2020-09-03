use crate::{
    chains::Blockchain,
    convert::{error::ConversionError, json::keyfile::EthereumJsonV3File},
    hdwallet::{bip32::generate_key, WManager},
    storage::{
        addressbook::AddressbookStorage,
        archive::{Archive, ArchiveType},
        error::VaultError,
    },
    structs::{
        pk::PrivateKeyHolder,
        seed::{Seed, SeedRef, SeedSource},
        types::HasUuid,
        wallet::{PKType, Wallet, WalletEntry},
    },
    EthereumAddress,
};
use hdpath::StandardHDPath;
use regex::Regex;
use std::{
    convert::{TryFrom, TryInto},
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};
use uuid::Uuid;

/// Compound trait for a vault entry which is stored in a separate file each
pub trait VaultAccessByFile<P>: VaultAccess<P> + SingleFileEntry
where
    P: HasUuid + Ord,
{
}

pub struct VaultStorage {
    pub dir: PathBuf,

    keys: Arc<dyn VaultAccessByFile<PrivateKeyHolder>>,
    wallets: Arc<dyn VaultAccessByFile<Wallet>>,
    seeds: Arc<dyn VaultAccessByFile<Seed>>,
}

struct StandardVaultFiles {
    dir: PathBuf,
    suffix: String,
}

/// Main interface to the Emerald Vault storage
impl VaultStorage {
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
            keys: self.keys(),
            wallets: self.wallets(),
            seeds: self.seeds(),
        }
    }
    pub fn addressbook(&self) -> AddressbookStorage {
        AddressbookStorage::from_path(self.dir.clone().join("addressbook.csv"))
    }
    pub fn add_entry(&self, wallet_id: Uuid) -> AddEntry {
        AddEntry {
            keys: self.keys().clone(),
            seeds: self.seeds().clone(),
            wallets: self.wallets().clone(),
            wallet_id,
        }
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
    keys: Arc<dyn VaultAccessByFile<PrivateKeyHolder>>,
    wallets: Arc<dyn VaultAccessByFile<Wallet>>,
    #[allow(dead_code)]
    seeds: Arc<dyn VaultAccessByFile<Seed>>,
}

impl CreateWallet {
    ///Create a new Wallet with the the specified Ethereum JSON Private Key. All fields for the wallet are set
    ///with default or empty values. The labels is set from JSON name field, if available.
    ///
    ///Returns UUID of the newly created wallet
    pub fn ethereum(
        &self,
        json: &EthereumJsonV3File,
        blockchain: Blockchain,
    ) -> Result<Uuid, VaultError> {
        let mut pk = PrivateKeyHolder::try_from(json)?;
        pk.generate_id();
        let wallet = Wallet {
            label: json.name.clone(),
            entries: vec![WalletEntry {
                id: 0,
                blockchain,
                address: json.address,
                key: PKType::PrivateKeyRef(pk.get_id()),
                ..WalletEntry::default()
            }],
            ..Wallet::default()
        };
        let result = wallet.get_id();
        self.keys.add(pk)?;
        self.wallets.add(wallet)?;
        Ok(result)
    }

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
        let pk = PrivateKeyHolder::create_ethereum_raw(pk, password)
            .map_err(|_| VaultError::InvalidDataError("Invalid PrivateKey".to_string()))?;
        let wallet = Wallet {
            entries: vec![WalletEntry {
                id: 0,
                blockchain,
                address: pk.get_ethereum_address(),
                key: PKType::PrivateKeyRef(pk.get_id()),
                ..WalletEntry::default()
            }],
            ..Wallet::default()
        };
        let result = wallet.get_id();
        self.keys.add(pk)?;
        self.wallets.add(wallet)?;
        Ok(result)
    }
}

pub struct AddEntry {
    keys: Arc<dyn VaultAccessByFile<PrivateKeyHolder>>,
    seeds: Arc<dyn VaultAccessByFile<Seed>>,
    wallets: Arc<dyn VaultAccessByFile<Wallet>>,
    wallet_id: Uuid,
}

impl AddEntry {
    pub fn ethereum(
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
            address: json.address,
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
        let address = pk.get_ethereum_address().clone();
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
        let seed = self.seeds.get(seed_id)?;
        let address = match seed.source {
            SeedSource::Bytes(seed) => {
                if password.is_none() {
                    return Err(VaultError::PasswordRequired);
                }
                let seed = seed.decrypt(password.unwrap().as_str())?;
                let ephemeral_pk = generate_key(&hd_path, seed.as_slice())?;
                Some(ephemeral_pk.to_address())
            }
            SeedSource::Ledger(_) => {
                // try to verify address if Ledger is currently connected
                let hd_path_bytes = Some(hd_path.to_bytes());
                let mut manager = WManager::new(hd_path_bytes.clone())?;
                manager.update(None)?;
                if manager.devices().is_empty() {
                    // not connected
                    None
                } else {
                    let fd = &manager.devices()[0].1;
                    Some(manager.get_address(fd, hd_path_bytes)?)
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
            address: address.or(expected_address),
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
        convert::json::keyfile::EthereumJsonV3File,
        structs::pk::{EthereumPk3, PrivateKeyHolder},
        tests::{read_dir_fully, *},
    };
    use chrono::{TimeZone, Utc};
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

        let mut seed = Seed::generate(None, "testtest").unwrap();
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

        let mut seed = Seed::generate(None, "testtest").unwrap();
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

        let mut seed = Seed::generate(None, "testtest").unwrap();
        seed.id = Uuid::parse_str("13052693-c51c-4e8b-91b3-564d3cb78fb4").unwrap();
        // 2 jan 2020
        seed.created_at = Utc.timestamp_millis(1577962800000);
        vault.seeds.add(seed.clone()).unwrap();

        let mut seed = Seed::generate(None, "testtest").unwrap();
        seed.id = Uuid::parse_str("5e47360d-3dc2-4b39-b399-75fbdd4ac020").unwrap();
        seed.created_at = Utc.timestamp_millis(0);
        vault.seeds.add(seed.clone()).unwrap();

        let mut seed = Seed::generate(None, "testtest").unwrap();
        seed.id = Uuid::parse_str("36805dff-a6e0-434d-be7d-5ef7931522d0").unwrap();
        // 1 jan 2020
        seed.created_at = Utc.timestamp_millis(1577876400000);
        vault.seeds.add(seed.clone()).unwrap();

        let mut seed = Seed::generate(None, "testtest").unwrap();
        seed.id = Uuid::parse_str("067e14c4-85de-421e-9957-48a1cdef42ae").unwrap();
        seed.created_at = Utc.timestamp_millis(0);
        vault.seeds.add(seed.clone()).unwrap();

        //first comes items without date
        //#4 -> #2
        //then ordered date
        //#3 -> #1

        let seeds = vault.seeds.list_entries().unwrap();
        assert_eq!(seeds.get(0).unwrap().id.to_string(),
                   "067e14c4-85de-421e-9957-48a1cdef42ae".to_string());
        assert_eq!(seeds.get(1).unwrap().id.to_string(),
                   "5e47360d-3dc2-4b39-b399-75fbdd4ac020".to_string());
        assert_eq!(seeds.get(2).unwrap().id.to_string(),
                   "36805dff-a6e0-434d-be7d-5ef7931522d0".to_string());
        assert_eq!(seeds.get(3).unwrap().id.to_string(),
                   "13052693-c51c-4e8b-91b3-564d3cb78fb4".to_string());
    }

    #[test]
    fn order_wallets_by_date_and_id() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        vault.wallets.add(Wallet {
            id: Uuid::parse_str("13052693-c51c-4e8b-91b3-564d3cb78fb4").unwrap(),
            // 2 jan 2020
            created_at: Utc.timestamp_millis(1577962800000),
            ..Wallet::default()
        }).unwrap();
        vault.wallets.add(Wallet {
            id: Uuid::parse_str("5e47360d-3dc2-4b39-b399-75fbdd4ac020").unwrap(),
            created_at: Utc.timestamp_millis(0),
            ..Wallet::default()
        }).unwrap();
        vault.wallets.add(Wallet {
            id: Uuid::parse_str("36805dff-a6e0-434d-be7d-5ef7931522d0").unwrap(),
            // 1 jan 2020
            created_at: Utc.timestamp_millis(1577876400000),
            ..Wallet::default()
        }).unwrap();
        vault.wallets.add(Wallet {
            id: Uuid::parse_str("067e14c4-85de-421e-9957-48a1cdef42ae").unwrap(),
            created_at: Utc.timestamp_millis(0),
            ..Wallet::default()
        }).unwrap();

        //first comes items without date
        //#4 -> #2
        //then ordered date
        //#3 -> #1

        let seeds = vault.wallets.list_entries().unwrap();
        assert_eq!(seeds.get(0).unwrap().id.to_string(),
                   "067e14c4-85de-421e-9957-48a1cdef42ae".to_string());
        assert_eq!(seeds.get(1).unwrap().id.to_string(),
                   "5e47360d-3dc2-4b39-b399-75fbdd4ac020".to_string());
        assert_eq!(seeds.get(2).unwrap().id.to_string(),
                   "36805dff-a6e0-434d-be7d-5ef7931522d0".to_string());
        assert_eq!(seeds.get(3).unwrap().id.to_string(),
                   "13052693-c51c-4e8b-91b3-564d3cb78fb4".to_string());
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
            .add_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let id2 = vault
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        let id2 = vault
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_entry(wallet_id.clone())
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
            .add_entry(wallet_id.clone())
            .raw_pk(
                hex::decode("fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd")
                    .unwrap(),
                "test",
                Blockchain::Ethereum,
            )
            .unwrap();
        assert_eq!(0, id1);
        let id2 = vault
            .add_entry(wallet_id.clone())
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
