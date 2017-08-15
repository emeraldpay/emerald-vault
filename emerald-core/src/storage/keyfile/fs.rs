//! # KeyFile storage within filesystem


use super::{AccountInfo, KeyfileStorage};
use super::error::Error;
use core::Address;
use keystore::{CryptoType, KeyFile};
use keystore::try_extract_address;
use rustc_serialize::json;
use std::ffi::OsStr;
use std::fs::{self, File, read_dir};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use util;

/// Filesystem storage for `KeyFiles`
///
pub struct FsStorage {
    /// Parent directory for storage
    base_path: PathBuf,
}

/// Result for searching `KeyFile` in `base_path`
/// and it subdirectories
///
struct SearchResult {
    /// Path to target `KeyFile`
    path: PathBuf,

    /// Decoded `KeyFile`
    kf: KeyFile,
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
        FsStorage { base_path: PathBuf::from(&dir) }
    }

    /// Search for `KeyFile` by specified `Address`
    ///
    /// # Arguments:
    ///
    /// * addr - target address
    ///
    fn search(&self, addr: &Address) -> Result<SearchResult, Error> {
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
                    let kf = KeyFile::decode(content)?;

                    return Ok(SearchResult { path: path, kf: kf });
                }
                _ => continue,
            }
        }

        Err(Error::NotFound(addr.to_string()))
    }

    /// Hides/unhides `Keyfile` for specified `Address`
    ///
    /// # Arguments:
    ///
    /// * addr - target address
    /// * is_visible - visibility flag
    ///
    fn toogle_visibility(&self, addr: &Address, is_visible: bool) -> Result<(), Error> {
        let mut res = self.search(addr)?;

        res.kf.visible = Some(is_visible);
        self.delete(&res.kf.address)?;
        FsStorage::put_with_name(&res.kf, &res.path)?;

        Ok(())
    }

    /// Put new `Keyfile` with specified name inside storage
    /// Uses absolute `path` appended with `KeyFile` name
    ///
    /// # Arguments:
    ///
    /// * kf - target `Keyfile`
    /// * path - path for insertion
    ///
    fn put_with_name<P: AsRef<Path>>(kf: &KeyFile, path: P) -> Result<(), Error> {
        let json = json::encode(&kf)?;
        let mut file = File::create(&path)?;
        file.write_all(json.as_ref()).ok();

        Ok(())
    }
}

impl KeyfileStorage for FsStorage {
    fn put(&self, kf: &KeyFile) -> Result<(), Error> {
        let name = generate_filename(&kf.uuid.to_string());
        let p: PathBuf = self.base_path.clone();
        let p_ref: &Path = p.as_ref();
        let path = p_ref.join(name);

        FsStorage::put_with_name(&kf, path)
    }

    fn delete(&self, addr: &Address) -> Result<(), Error> {
        let res = self.search(addr)?;

        match fs::remove_file(res.path) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::StorageError(
                format!("Can't delete KeyFile for address: {}", addr),
            )),
        }
    }

    fn search_by_address(&self, addr: &Address) -> Result<KeyFile, Error> {
        let res = self.search(addr)?;
        Ok(res.kf)
    }

    fn list_accounts(&self, show_hidden: bool) -> Result<Vec<AccountInfo>, Error> {
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

                match KeyFile::decode(content) {
                    Ok(kf) => {
                        let mut info = AccountInfo::default();
                        if kf.visible.is_none() || kf.visible.unwrap() || show_hidden {
                            info.is_hardware = match kf.crypto {
                                CryptoType::Core(_) => false,
                                CryptoType::HdWallet(_) => true,
                            };

                            if let Some(name) = kf.name {
                                info.name = name;
                            };

                            if let Some(desc) = kf.description {
                                info.description = desc;
                            };

                            accounts.push(info);
                        }
                    }
                    Err(_) => info!("Invalid keystore file format for: {:?}", entry.file_name()),
                }
            }
        }

        Ok(accounts)
    }

    /// Hides account for given address from being listed
    ///
    /// #Arguments
    /// addr - target address
    ///
    fn hide(&self, addr: &Address) -> Result<bool, Error> {
        self.toogle_visibility(&addr, false)?;

        Ok(true)
    }

    /// Unhides account for given address from being listed
    ///
    /// #Arguments
    /// addr - target address
    ///
    fn unhide(&self, addr: &Address) -> Result<bool, Error> {
        self.toogle_visibility(&addr, true)?;

        Ok(true)
    }
}

/// Creates filename for keystore file in format:
/// `UTC--yyy-mm-ddThh-mm-ssZ--uuid`
///
/// # Arguments
///
/// * `uuid` - UUID for keyfile
///
pub fn generate_filename(uuid: &str) -> String {
    format!("UTC--{}Z--{}", &util::timestamp(), &uuid)
}
