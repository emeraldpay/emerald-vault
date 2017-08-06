//! # Storage for `Keystore` files


use super::error::Error;
use super::{ChainStorage, Storages, default_keystore_path, default_path};
use super::KeyfileStorage;

use util;
use core::Address;
use keystore::{CryptoType, KeyFile};
use keystore::{SerializableKeyFileCore, SerializableKeyFileHD};
use rocksdb::{DB, IteratorMode};
use rustc_serialize::{Encodable, Encoder, json};
use std::fs::{self, File, read_dir};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str;

/// Dtabase backed storage for `Keyfile`
///
pub struct dbStorage {
    ///
    pub db: DB,
}

impl dbStorage {
    ///
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<dbStorage, Error> {
        let db = DB::open_default(dir)?;

        Ok(dbStorage { db: db })
    }

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

impl KeyfileStorage for dbStorage {
    fn put(&self, kf: &KeyFile) -> Result<(), Error> {
        let json = json::encode(&kf)?;
        self.db.put(&kf.address, json.as_ref())?;

        Ok(())
    }

    ///
    fn delete(&self, addr: &Address) -> Result<(), Error> {
        self.db.delete(&addr)?;

        Ok(())
    }

    /// Search of `KeyFile` by specified `Address`
    ///
    fn search_by_address(&self, addr: &Address) -> Result<KeyFile, Error> {
        let bytes = self.db.get(&addr)?;
        let str = bytes
            .and_then(|d| d.to_utf8().and_then(|v| Some(v.to_string())))
            .ok_or(Error::StorageError("Can't parse KeyFile data".to_string()))?;
        let kf = KeyFile::decode(str)?;

        Ok(kf)
    }

    /// Hides account for given address from being listed
    ///
    fn hide(&self, addr: &Address) -> Result<bool, Error> {
        let mut kf = self.search_by_address(&addr)?;

        kf.visible = Some(false);
        self.put(&kf)?;

        Ok(true)
    }

    /// Unhides account for given address from being listed
    ///
    fn unhide(&self, addr: &Address) -> Result<bool, Error> {
        let mut kf = self.search_by_address(&addr)?;

        kf.visible = Some(true);
        self.put(&kf)?;

        Ok(true)
    }

    /// Lists addresses for `Keystore` files in specified folder.
    /// Can include hidden files if flag set.
    ///
    /// # Arguments
    ///
    /// * `path` - target directory
    /// * `showHidden` - flag to show hidden `Keystore` files
    ///
    /// # Return:
    /// Array of tuples (name, address, description, is_hidden)
    ///
    fn list_accounts(
        &self,
        show_hidden: bool,
    ) -> Result<Vec<(String, String, String, bool)>, Error> {
        let mut accounts: Vec<(String, String, String, bool)> = vec![];

        for (addr, val) in self.db.iterator(IteratorMode::Start) {
            let str = str::from_utf8(&val)?;
            match KeyFile::decode(str.to_string()) {
                Ok(kf) => {
                    let mut info = Vec::new();
                    if kf.visible.is_none() || kf.visible.unwrap() || show_hidden {
                        let is_hd = match kf.crypto {
                            CryptoType::Core(_) => false,
                            CryptoType::HdWallet(_) => true,
                        };
                        match kf.name {
                            Some(name) => info.push(name),
                            None => info.push("".to_string()),
                        }

                        match kf.description {
                            Some(desc) => info.push(desc),
                            None => info.push("".to_string()),
                        }
                        accounts.push((
                            info[0].clone(),
                            kf.address.to_string(),
                            info[1].clone(),
                            is_hd,
                        ));
                    }
                }
                Err(_) => {
                    let data: [u8; 20] = util::to_arr(&*addr);
                    info!(
                        "Invalid keystore file format for addr: {}",
                        Address::from(data)
                    )
                }
            }
        }

        Ok(accounts)
    }
}
