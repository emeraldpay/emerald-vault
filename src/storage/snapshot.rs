use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use crate::error::VaultError;
use crate::storage::global_key;
use crate::storage::vault::VaultStorage;
use crate::structs::crypto::GlobalKey;

///
/// Subdirectory of the Vault to keep Snapshots
const DIR: &'static str = "snapshots";
///
/// Extension of a snapshto file
const EXTENSION: &'static str = "emrldvault";

///
/// Manage Snapshot Extraction
///
/// The process goes in the following order:
/// 1. A client must write content of an existing snapshot (it implements `Write`)
/// 2. (Optionally) Verify password with [SnapshotRestore::verify_password]
/// 3. Run [SnapshotRestore::complete] to extract and _replace_ the current Vault or [SnapshotRestore::cancel]
///
/// Example:
/// ```ignore
/// # use std::fs::File;
/// # use emerald_vault::error::VaultError;
/// # use emerald_vault::storage::snapshot::Snapshots;
///
/// let snapshots: Snapshots;
/// let mut existing: dyn Read;
///
/// let mut restore = snapshots.restore()?;
/// let copied = std::io::copy(&mut existing, &mut restore)?;
/// let password_check = restore.verify_password("test")?;
/// if !password_check {
///     restore.cancel()
/// } else {
///    restore.complete()?
/// }
/// ```
pub struct SnapshotRestore {
    pub id: Uuid,
    vault_dir: PathBuf,
    filename: PathBuf,
    file: File,
}

impl SnapshotRestore {

    fn read_file(&mut self, name: &str) -> Result<Option<Vec<u8>>, VaultError> {
        self.file.flush()?;
        self.file.seek(SeekFrom::Start(0))?;

        let mut zip = zip::ZipArchive::new(&self.file)
            .map_err(|e| VaultError::InvalidDataError(
                format!("Not a Snapshot file: {}", e)
            ))?;
        for i in 0..zip.len()
        {
            let mut file = zip.by_index(i).unwrap();
            if file.is_file() && file.name() == name {
                let mut result = vec![];
                let _ = file.read_to_end(&mut result).unwrap();
                return Ok(Some(result))
            }
        }
        Ok(None)
    }

    /// Verify file for a prepared snapshot.
    /// It doesn't modify the Vault and operates directly on snapshot file, so it's safe to run the function before actual extraction.
    pub fn verify_password<S: AsRef<str>>(&mut self, password: S) -> Result<bool, VaultError> {
        let global_key = self.read_file(global_key::KEY_FILE)?;
        if global_key.is_none() {
            return Err(VaultError::GlobalKeyRequired)
        }
        let global_key = GlobalKey::try_from(global_key.unwrap().as_slice())?;
        global_key.verify_password(password.as_ref())
            .map_err(|e| VaultError::from(e))
    }

    ///
    /// Exctract Vault files to the Vault and delete the snapshot
    pub fn complete(mut self) -> Result<(), VaultError> {
        self.file.flush()?;
        self.file.seek(SeekFrom::Start(0))?;

        let mut zip = zip::ZipArchive::new(self.file)
            .map_err(|e| VaultError::InvalidDataError(
                format!("Not a Snapshot file: {}", e)
            ))?;
        for i in 0..zip.len()
        {
            let mut file = zip.by_index(i).unwrap();
            let ext = Path::new(file.name()).extension().unwrap();
            if VaultStorage::is_vault_ext(ext) {
                let target = self.vault_dir.join(file.name());
                if target.exists() {
                    //TODO move to archive instead
                    fs::remove_file(target.clone())?;
                }
                let mut target = File::create(target).unwrap();
                let _ = std::io::copy(&mut file, &mut target)?;
            }
        }
        let deleted = fs::remove_file(self.filename);
        if deleted.is_err() {
            debug!("Snapshot not deleted: {}", deleted.err().unwrap())
        }
        Ok(())
    }

    ///
    /// Delete the snapshot without actul extraction
    pub fn cancel(mut self) {
        // slush just in case it's going to be called after the deletion
        let flush = self.file.flush();
        if flush.is_err() {
            debug!("Snapshot not flushed: {}", flush.err().unwrap())
        }
        let deleted = fs::remove_file(self.filename);
        if deleted.is_err() {
            debug!("Snapshot not deleted: {}", deleted.err().unwrap())
        }
    }
}

impl Write for SnapshotRestore {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

///
/// Manages the snapshots.
/// A _snapshot_ is a file containing all critical elements of a vault, ex. wallets, keys and seeds.
/// Snapshot is usually used to backup/restore or to copy the Vault to another place.
///
/// Internally a snapshot is a Zip file containing main files of a Vault. The filename is `<UUID>.emrldvault`.
/// During the backup/restore it keeps the files inside the `/snapshots` dir under the Vault.
pub struct Snapshots {
    vault_dir: PathBuf,
}

impl Snapshots {

    ///
    /// Opens Snapshots for the specified `vault`
    pub fn open(vault: &VaultStorage) -> Snapshots {
        Snapshots {
            vault_dir: vault.dir.clone(),
        }
    }

    ///
    /// Makes sure that the snapshots dir is available
    fn ensure_created(&self) -> Result<(), VaultError> {
        let dir = self.vault_dir.join(DIR);
        if dir.exists() {
            return if dir.is_dir() {
                Ok(())
            } else {
                Err(VaultError::FilesystemError("Snapshots dir is locked".to_string()))
            }
        }
        let _ = fs::create_dir_all(&dir)?;
        Ok(())
    }

    ///
    /// Get a snapshot filename for snapshot with specified `id`. The file may not exists, the function just operate filenames.
    fn get_filename_for(&self, id: Uuid) -> Result<PathBuf, VaultError> {
        let _ = self.ensure_created()?;
        let filename = format!("{}.{}", id, EXTENSION);
        Ok(self.vault_dir.join(DIR).join(filename))
    }

    ///
    /// Creates a new snapshot. Returns its UUID to read from the snapshot.
    pub fn create(&self) -> Result<Uuid, VaultError> {
        let id = Uuid::new_v4();

        let filename = self.get_filename_for(id)?;
        let f = File::create(filename)?;
        let mut zip = zip::ZipWriter::new(f);

        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        let files = fs::read_dir(&self.vault_dir)?;
        for entry in files {
            if let Ok(entry) = entry {
                let path = entry.path();
                // make sure we archive files, not directories which may be created by mistake / maliciously
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if VaultStorage::is_vault_ext(ext) {
                            let file_name = path.file_name().unwrap().to_str().unwrap();
                            zip.start_file(file_name, options)
                                .map_err(|_| VaultError::FilesystemError("Cannot write snapshot".to_string()))?;
                            let mut src = File::open(path).unwrap();
                            let _ = std::io::copy(&mut src, &mut zip)?;
                        }
                    }
                }
            }
        }

        zip.finish()
            .map_err(|_| VaultError::FilesystemError("Cannot write snapshot".to_string()))?;

        Ok(id)
    }

    ///
    /// Get a reader for the specified `id`. Returns error if the snapshot is not available.
    pub fn read(&self, id: Uuid) -> Result<Box<dyn Read>, VaultError> {
        let filename = self.get_filename_for(id)?;
        if !filename.exists() {
            return Err(VaultError::FilesystemError("Snaphsot is not ready".to_string()));
        }
        let f = File::open(filename)?;
        Ok(Box::new(f))
    }

    ///
    /// Starts a snapshot extraction process. See [SnapshotRestore] for details
    pub fn restore(&self) -> Result<SnapshotRestore, VaultError> {
        let id = Uuid::new_v4();
        let filename = self.get_filename_for(id)?;
        let file = OpenOptions::new()
            // need it to be a new writable file to write an existing snapshot
            .write(true).create(true).truncate(true)
            // also must be readable to read from the file once its written
            .read(true)
            .open(&filename)?;
        Ok(SnapshotRestore {
            id,
            file,
            filename,
            vault_dir: self.vault_dir.clone(),
        })
    }

    ///
    /// Open an existing snapshot to restore from it
    pub fn open_restore(&self, id: Uuid) -> Result<SnapshotRestore, VaultError> {
        let filename = self.get_filename_for(id)?;
        let file = OpenOptions::new()
            // only readable since we expect it only to access existing
            .read(true)
            .open(&filename)?;
        Ok(SnapshotRestore {
            id,
            file,
            filename,
            vault_dir: self.vault_dir.clone(),
        })
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use std::str::FromStr;
    use hdpath::StandardHDPath;
    use tempdir::TempDir;
    use crate::chains::Blockchain;
    use crate::EthereumAddress;
    use crate::mnemonic::{Language, Mnemonic};
    use crate::storage::snapshot::Snapshots;
    use crate::storage::vault::VaultStorage;
    use crate::structs::seed::{Seed, SeedSource};
    use crate::structs::wallet::Wallet;

    #[test]
    fn backup_and_restore() {
        let tmp_dir_1 = TempDir::new("emerald-vault-test").unwrap();
        let vault_1 = VaultStorage::create(tmp_dir_1.path()).unwrap();

        vault_1.global_key().create("test").unwrap();

        let phrase = Mnemonic::try_from(
            Language::English,
            "quote ivory blast onion below kangaroo tonight spread awkward decide farm gun exact wood brown",
        ).unwrap();
        let seed = Seed {
            source: SeedSource::create_raw(phrase.seed(None))
                .unwrap()
                .reencrypt(SeedSource::nokey().as_bytes(), "test".as_bytes(), vault_1.global_key().get().unwrap())
                .unwrap(),
            ..Seed::default()
        };
        let wallet = Wallet::default();

        vault_1.seeds().add(seed.clone()).unwrap();
        vault_1.wallets().add(wallet.clone()).unwrap();
        vault_1.add_ethereum_entry(wallet.id.clone())
            .seed_hd(seed.id.clone(),
                     StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap(), Blockchain::Ethereum,
                     Some("test".to_string()),
                     Some(EthereumAddress::from_str("0x77F43e8e5d6E0D7F647B71c49102B49448f4749D").unwrap()))
            .unwrap();

        let snapshots_1 = Snapshots::open(&vault_1);
        let snap = snapshots_1.create().unwrap();
        let mut snap_reader = snapshots_1.read(snap).unwrap();

        let tmp_dir_2 = TempDir::new("emerald-vault-test").unwrap();
        let vault_2 = VaultStorage::create(tmp_dir_2.path()).unwrap();
        let snapshots_2 = Snapshots::open(&vault_2);
        let mut restore = snapshots_2.restore().unwrap();
        let copied = std::io::copy(&mut snap_reader, &mut restore).unwrap();
        assert!(copied > 0);

        let password_check = restore.verify_password("test").unwrap();
        assert!(password_check);
        let password_check_wrong = restore.verify_password("test-wrong").unwrap();
        assert!(!password_check_wrong);

        restore.complete().unwrap();

        assert!(vault_2.global_key().is_set());
        let password_check_vault = vault_2.global_key().verify_password("test").unwrap();
        assert!(password_check_vault);

        let seeds = vault_2.seeds().list_entries().unwrap();
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].id, seed.id);
        let wallets = vault_2.wallets().list_entries().unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].id, wallet.id);

    }
}
