//! # Storage for `Keystore` files

mod error;
pub mod storage;

pub use self::storage::{Storages, ChainStorage, default_keystore_path, default_path};

use self::error::Error;
use keystore::{KeyFile};
use keystore::{SerializableKeyFileHD, SerializableKeyFileCore};
use core::{Address};
use std::fs::{self, File, read_dir};
use std::io::{Read, Write};
use rocksdb::DB;
use std::path::{Path, PathBuf};
use rustc_serialize::{Encodable, Encoder, json};

/// Storage controller for `Keyfile`
///
pub struct KeyfileStorage {
    db: DB
}

impl KeyfileStorage {
    ///
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<KeyfileStorage, Error> {
        let db = DB::open_default(dir)?;

        Ok(KeyfileStorage {
            db: db
        })
    }

    /// Serializes into JSON file with the name format `UTC--<timestamp>Z--<uuid>`
    ///
    /// # Arguments
    ///
    /// * `dir` - path to destination directory
    /// * `addr` - a public address (optional)
    ///
    pub fn flush(&self, kf: &KeyFile, filename: Option<&str>) -> Result<(), Error> {
        let tmp;
        let name = match filename {
            Some(n) => n,
            None => {
                tmp = KeyfileStorage::generate_filename(&kf.uuid.to_string());
                &tmp
            }
        };

        Ok(self.add(kf, name)?)
    }

    /// Writes out `Keyfile` into disk accordingly to `p` path
    /// Try to match one wvariant of KeyFile:
    ///     `..Core` - for normal `Keyfile` created as JSON safe storage
    ///     `..HD` - for usage with HD wallets
    ///
    /// #Arguments:
    /// kf - `Keyfile` to be written
    /// p - destination route (path + filename)
    ///
    pub fn add(&self, kf: &KeyFile, id: String) -> Result<(), Error> {
        let json = match SerializableKeyFileCore::try_from(kf.clone()) {
            Ok(sf) => json::encode(&sf)?,
            Err(_) => {
                match SerializableKeyFileHD::try_from(kf.clone()) {
                    Ok(sf) => json::encode(&sf)?,
                    Err(e) => return Err(Error::StorageError(e.to_string())),
                }
            }
        };


        self.db.put(id, json.as_ref())?;

        Ok(())
    }

//    /// Search of `KeyFile` by specified `Address`
//    /// Returns set of filepath and `Keyfile`
//    ///
//    /// # Arguments
//    ///
//    /// * `path` - path with keystore files
//    ///
//    pub fn search_by_address(
//        addr: &Address,
//        path: P,
//    ) -> Result<(PathBuf, KeyFile), Error> {
//        let entries = fs::read_dir(path)?;
//
//        for entry in entries {
//            let path = entry?.path();
//
//            if path.is_dir() {
//                continue;
//            }
//
//            let mut file = fs::File::open(&path)?;
//            let mut content = String::new();
//
//            if file.read_to_string(&mut content).is_err() {
//                continue;
//            }
//
//            match try_extract_address(&content) {
//                Some(a) if a == *addr => {
//                    let kf = KeyFile::decode(content)?;
//                    return Ok((path.to_owned(), kf));
//                }
//                _ => continue,
//            }
//        }
//
//        Err(Error::NotFound)
//    }

//    /// Lists addresses for `Keystore` files in specified folder.
//    /// Can include hidden files if flag set.
//    ///
//    /// # Arguments
//    ///
//    /// * `path` - target directory
//    /// * `showHidden` - flag to show hidden `Keystore` files
//    ///
//    /// # Return:
//    /// Array of tuples (name, address, description, is_hidden)
//    ///
//    pub fn list_accounts(
//        show_hidden: bool,
//    ) -> Result<Vec<(String, String, String, bool)>, Error> {
//        let mut accounts: Vec<(String, String, String, bool)> = vec![];
//        for e in read_dir(&path)? {
//            if e.is_err() {
//                continue;
//            }
//            let entry = e.unwrap();
//            let mut content = String::new();
//            if let Ok(mut keyfile) = File::open(entry.path()) {
//                if keyfile.read_to_string(&mut content).is_err() {
//                    continue;
//                }
//
//                match KeyFile::decode(content) {
//                    Ok(kf) => {
//                        let mut info = Vec::new();
//                        if kf.visible.is_none() || kf.visible.unwrap() || show_hidden {
//                            let is_hd = match kf.crypto {
//                                CryptoType::Core(_) => false,
//                                CryptoType::HdWallet(_) => true,
//                            };
//                            match kf.name {
//                                Some(name) => info.push(name),
//                                None => info.push("".to_string()),
//                            }
//
//                            match kf.description {
//                                Some(desc) => info.push(desc),
//                                None => info.push("".to_string()),
//                            }
//                            accounts.push((
//                                info[0].clone(),
//                                kf.address.to_string(),
//                                info[1].clone(),
//                                is_hd,
//                            ));
//                        }
//                    }
//                    Err(_) => info!("Invalid keystore file format for: {:?}", entry.file_name()),
//                }
//            }
//        }
//
//        Ok(accounts)
//    }

//    /// Hides account for given address from being listed
//    ///
//    /// #Arguments
//    /// addr - target address
//    /// path - folder with keystore files
//    ///
//    pub fn hide(addr: &Address) -> Result<bool, Error> {
//        let (p, mut kf) = KeyFile::search_by_address(addr, &path)?;
//
//        kf.visible = Some(false);
//        write(&kf, &p)?;
//
//        Ok(true)
//    }
//
//    /// Unhides account for given address from being listed
//    ///
//    /// #Arguments
//    /// addr - target address
//    /// path - folder with keystore files
//    ///
//    pub fn unhide(addr: &Address) -> Result<bool, Error> {
//        let (p, mut kf) = KeyFile::search_by_address(addr)?;
//
//        kf.visible = Some(true);
//        write(&kf, &p)?;
//
//        Ok(true)
//    }

    /// Creates filename for keystore file in format:
    /// `UTC--yyy-mm-ddThh-mm-ssZ--uuid`
    ///
    /// # Arguments
    ///
    /// * `uuid` - UUID for keyfile
    ///
    fn generate_filename(uuid: &str) -> String {
        format!("UTC--{}Z--{}", &util::timestamp(), &uuid)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn should_add() {

    }
}
