//! # Storage for `Keystore` files


use super::KeyfileStorage;
use super::error::Error;
use core::Address;
use keystore::{CryptoType, KeyFile};
use rocksdb::{DB, IteratorMode};
use rustc_serialize::json;
use std::path::Path;
use std::str;

use util;

/// Dtabase backed storage for `Keyfile`
///
pub struct DbStorage {
    ///
    pub db: DB,
}

impl DbStorage {
    ///
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<DbStorage, Error> {
        let db = DB::open_default(dir)?;

        Ok(DbStorage { db: db })
    }
}

impl KeyfileStorage for DbStorage {
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
            .ok_or(Error::NotFound(addr.to_string()))?;
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
