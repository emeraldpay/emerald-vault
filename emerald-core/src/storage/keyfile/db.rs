//! # Storage for `Keystore` files


use super::{AccountInfo, KeyfileStorage, generate_filename};
use super::error::Error;
use core::Address;
use keystore::KeyFile;
use rocksdb::{DB, DBVector, IteratorMode};
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
    /// Storage structure:
    ///     key - `Address`
    ///     value - `Filename`+ `:` + `Keyfile_json`
    ///
    /// # Arguments:
    ///
    /// * dir - parent folder
    ///
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<DbStorage, Error> {
        let db = DB::open_default(dir)?;

        Ok(DbStorage { db: db })
    }

    /// Splits value into filename and `Keyfile` json
    ///
    /// # Arguments:
    ///
    /// * dir - parent folder
    ///
    /// # Return:
    ///
    /// Tuple of `String` (<filename>, <keyfile_json>)
    ///
    fn split(bytes: Option<DBVector>) -> Result<(String, String), Error> {
        let val = bytes
            .and_then(|d| {
                d.to_utf8().and_then(|v| {
                    let val = v.to_string();
                    let arr: Vec<&str> = val.split(":").collect();
                    Some((arr[0].to_string(), arr[1].to_string()))
                })
            })
            .ok_or(Error::NotFound("Can't extract filename".to_string()))?;

        Ok(val)
    }
}

impl KeyfileStorage for DbStorage {
    fn put(&self, kf: &KeyFile) -> Result<(), Error> {
        let json = json::encode(&kf)?;
        let val = generate_filename(&kf.uuid.to_string()) + ":" + &json;
        self.db.put(&kf.address, &val.as_bytes())?;

        Ok(())
    }

    fn delete(&self, addr: &Address) -> Result<(), Error> {
        self.db.delete(&addr)?;

        Ok(())
    }

    fn search_by_address(&self, addr: &Address) -> Result<KeyFile, Error> {
        let vec = self.db.get(&addr)?;
        let (_, json) = DbStorage::split(vec)?;
        let kf = KeyFile::decode(json)?;

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

        unsafe {
            for (addr, mut val) in self.db.iterator(IteratorMode::Start) {
                let vec = DBVector::from_c(val.as_mut_ptr(), val.len());
                let (filename, json) = DbStorage::split(Some(vec))?;

                match KeyFile::decode(json) {
                    Ok(kf) => {
                        if kf.visible.is_none() || kf.visible.unwrap() || show_hidden {
                            let mut info = AccountInfo::from(kf);
                            info.filename = filename;
                            accounts.push(info);
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
        }

        Ok(accounts)
    }
}
