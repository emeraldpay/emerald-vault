//! # `KeyFile` storage within filesystem

use super::error::KeystoreError;
use super::{generate_filename, AccountInfo, KeyfileStorage};
use core::Address;
use keystore::try_extract_address;
use keystore::KeyFile;

use serde_json;
use std::ffi::OsStr;
use std::fs::{self, read_dir, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Filesystem storage for `KeyFiles`
///
pub struct FsStorage {
    /// Parent directory for storage
    base_path: PathBuf,
}

impl FsStorage {
    /// Create new `FsStorage`
    /// Uses specified path as parent folder
    ///
    /// # Arguments:
    ///
    /// * dir - parent folder
    ///
    pub fn new<P>(dir: P) -> FsStorage
    where
        P: AsRef<Path> + AsRef<OsStr>,
    {
        FsStorage {
            base_path: PathBuf::from(&dir),
        }
    }

    /// Hides/unhides `Keyfile` for specified `Address`
    ///
    /// # Arguments:
    ///
    /// * addr - target address
    /// * is_visible - visibility flag
    ///
    fn toogle_visibility(&self, addr: &Address, is_visible: bool) -> Result<(), KeystoreError> {
        let (info, mut kf) = self.search_by_address(addr)?;

        kf.visible = Some(is_visible);
        self.delete(&kf.address)?;

        self.put_with_name(&kf, &info.filename)
    }

    /// Creates path for specified keyfile name
    ///
    /// # Arguments:
    ///
    /// * name - filename
    ///
    fn build_path(&self, name: &str) -> PathBuf {
        let mut path = self.base_path.clone();
        path.push(name);
        path
    }

    /// Put new `Keyfile` with specified name inside storage
    /// Uses absolute `path` appended with `KeyFile` name
    ///
    /// # Arguments:
    ///
    /// * kf - target `Keyfile`
    /// * name - filename
    ///
    fn put_with_name(&self, kf: &KeyFile, name: &str) -> Result<(), KeystoreError> {
        let json = serde_json::to_string(&kf)?;
        let path = self.build_path(name);

        let mut file = File::create(&path)?;
        file.write_all(json.as_ref()).ok();

        Ok(())
    }
}

impl KeyfileStorage for FsStorage {
    fn put(&self, kf: &KeyFile) -> Result<(), KeystoreError> {
        let name = generate_filename(&kf.uuid.to_string());

        self.put_with_name(kf, &name)
    }

    fn delete(&self, addr: &Address) -> Result<(), KeystoreError> {
        let (info, _) = self.search_by_address(addr)?;
        let path = self.build_path(&info.filename);

        match fs::remove_file(path) {
            Ok(_) => Ok(()),
            Err(_) => Err(KeystoreError::StorageError(format!(
                "Can't delete KeyFile for address: {}",
                addr
            ))),
        }
    }

    fn search_by_address(&self, addr: &Address) -> Result<(AccountInfo, KeyFile), KeystoreError> {
        let entries = fs::read_dir(&self.base_path)?;

        for entry in entries {
            let path = entry?.path();

            if path.is_dir() {
                continue;
            }

            let mut file = fs::File::open(&path)?;
            let mut content = String::new();

            if file.read_to_string(&mut content).is_err() {
                continue;
            }

            match try_extract_address(&content) {
                Some(a) if a == *addr => {
                    let kf = KeyFile::decode(&content)?;
                    let mut info = AccountInfo::from(kf.clone());
                    info.filename = match path.file_name().and_then(|s| s.to_str()) {
                        Some(s) => s.to_string(),
                        None => {
                            return Err(KeystoreError::StorageError(format!(
                                "Invalid filename format for address {}",
                                addr
                            )))
                        }
                    };

                    return Ok((info, kf));
                }
                _ => continue,
            }
        }

        Err(KeystoreError::NotFound(addr.to_string()))
    }

    fn list_accounts(&self, show_hidden: bool) -> Result<Vec<AccountInfo>, KeystoreError> {
        let mut accounts = vec![];
        for e in read_dir(&self.base_path)? {
            if e.is_err() {
                continue;
            }
            let entry = e.unwrap();
            let mut content = String::new();
            if let Ok(mut keyfile) = File::open(entry.path()) {
                if keyfile.read_to_string(&mut content).is_err() {
                    continue;
                }

                match KeyFile::decode(&content) {
                    Ok(kf) => {
                        if kf.visible.is_none() || kf.visible.unwrap() || show_hidden {
                            let mut info = AccountInfo::from(kf);
                            match entry.path().file_name().and_then(|s| s.to_str()) {
                                Some(name) => {
                                    info.filename = name.to_string();
                                    accounts.push(info);
                                }
                                None => info!("Corrupted filename for: {:?}", entry.file_name()),
                            }
                        }
                    }
                    Err(_) => info!("Invalid keystore file format for: {:?}", entry.file_name()),
                }
            }
        }

        Ok(accounts)
    }

    fn hide(&self, addr: &Address) -> Result<bool, KeystoreError> {
        self.toogle_visibility(addr, false)?;

        Ok(true)
    }

    fn unhide(&self, addr: &Address) -> Result<bool, KeystoreError> {
        self.toogle_visibility(addr, true)?;

        Ok(true)
    }

    fn update(
        &self,
        addr: &Address,
        name: Option<String>,
        desc: Option<String>,
    ) -> Result<(), KeystoreError> {
        let (info, mut kf) = self.search_by_address(addr)?;

        if name.is_some() {
            kf.name = name;
        };

        if desc.is_some() {
            kf.description = desc;
        };
        self.delete(&kf.address)?;

        self.put_with_name(&kf, &info.filename)
    }
}
