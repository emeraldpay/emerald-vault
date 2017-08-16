//! # Storage for `Keystore` files


use super::{AccountInfo, KeyfileStorage};
use super::error::Error;
use core::Address;
use keystore::KeyFile;
use rocksdb::{DB, IteratorMode};
use rustc_serialize::json;
use std::path::Path;
use std::str;

use util;

/// Database backed storage for `KeyFile`
///
pub struct DbStorage {
    /// Database handler
    pub db: DB,
}

impl DbStorage {
    /// Create new database storage
    /// Use specified directory as parent folder
    ///
    /// # Arguments:
    ///
    /// * dir - parent folder
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

    fn delete(&self, addr: &Address) -> Result<(), Error> {
        self.db.delete(&addr)?;

        Ok(())
    }

    fn search_by_address(&self, addr: &Address) -> Result<KeyFile, Error> {
        let bytes = self.db.get(&addr)?;
        let str = bytes
            .and_then(|d| d.to_utf8().and_then(|v| Some(v.to_string())))
            .ok_or(Error::NotFound(addr.to_string()))?;
        let kf = KeyFile::decode(str)?;

        Ok(kf)
    }

    fn hide(&self, addr: &Address) -> Result<bool, Error> {
        let mut kf = self.search_by_address(&addr)?;

        kf.visible = Some(false);
        self.put(&kf)?;

        Ok(true)
    }

    fn unhide(&self, addr: &Address) -> Result<bool, Error> {
        let mut kf = self.search_by_address(&addr)?;

        kf.visible = Some(true);
        self.put(&kf)?;

        Ok(true)
    }

    fn list_accounts(&self, show_hidden: bool) -> Result<Vec<AccountInfo>, Error> {
        let mut accounts = vec![];

        for (addr, val) in self.db.iterator(IteratorMode::Start) {
            let str = str::from_utf8(&val)?;
            match KeyFile::decode(str.to_string()) {
                Ok(kf) => {
                    if kf.visible.is_none() || kf.visible.unwrap() || show_hidden {
                        accounts.push(AccountInfo::from(kf));
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
