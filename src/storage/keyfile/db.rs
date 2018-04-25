//! # Storage for `Keystore` files

use super::error::KeystoreError;
use super::{generate_filename, AccountInfo, KeyfileStorage};
use core::Address;
use keystore::KeyFile;
use rocksdb::{IteratorMode, DB};
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

/// Separator for composing value string
/// `value = <filename> + SEPARATOR + <keyfile_json>`
///
const SEPARATOR: &str = "<|>";

impl DbStorage {
    /// Create new database storage
    /// Use specified directory as parent folder
    /// Storage structure:
    ///     key - `Address`
    ///     value - `<filename> + SEPARATOR + <keyfile_json>`
    ///
    /// # Arguments:
    ///
    /// * dir - parent folder
    ///
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<DbStorage, KeystoreError> {
        let db = DB::open_default(dir)?;

        Ok(DbStorage { db })
    }

    /// Splits value into `filename` and `Keyfile` json
    ///
    /// # Arguments:
    ///
    /// * dir - parent folder
    ///
    /// # Return:
    ///
    /// Tuple of `String` (<filename>, <keyfile_json>)
    ///
    fn split(val: &str) -> Result<(String, String), KeystoreError> {
        let arr: Vec<&str> = val.split(SEPARATOR).collect();
        let json = arr[1..arr.len()].join(SEPARATOR);

        Ok((arr[0].to_string(), json))
    }
}

impl KeyfileStorage for DbStorage {
    fn put(&self, kf: &KeyFile) -> Result<(), KeystoreError> {
        let json = json::encode(&kf)?;
        let val = generate_filename(&kf.uuid.to_string()) + SEPARATOR + &json;
        self.db.put(&kf.address, val.as_bytes())?;

        Ok(())
    }

    fn delete(&self, addr: &Address) -> Result<(), KeystoreError> {
        self.db.delete(addr)?;

        Ok(())
    }

    fn search_by_address(&self, addr: &Address) -> Result<(AccountInfo, KeyFile), KeystoreError> {
        let dbvec = self.db.get(addr)?;

        let val = dbvec
            .and_then(|ref d| d.to_utf8().and_then(|v| Some(v.to_string())))
            .ok_or_else(|| KeystoreError::NotFound(format!("{}", addr)))?;
        let (filename, json) = DbStorage::split(&val)?;
        let kf = KeyFile::decode(&json)?;

        let mut info = AccountInfo::from(kf.clone());
        info.filename = filename;

        Ok((info, kf))
    }

    fn hide(&self, addr: &Address) -> Result<bool, KeystoreError> {
        let (_, mut kf) = self.search_by_address(addr)?;

        kf.visible = Some(false);
        self.put(&kf)?;

        Ok(true)
    }

    fn unhide(&self, addr: &Address) -> Result<bool, KeystoreError> {
        let (_, mut kf) = self.search_by_address(addr)?;

        kf.visible = Some(true);
        self.put(&kf)?;

        Ok(true)
    }

    fn list_accounts(&self, show_hidden: bool) -> Result<Vec<AccountInfo>, KeystoreError> {
        let mut accounts = vec![];

        for (addr, val) in self.db.iterator(IteratorMode::Start) {
            let vec = str::from_utf8(&val)?;
            let (filename, json) = DbStorage::split(vec)?;
            match KeyFile::decode(&json) {
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
                        "Invalid keystore file format for address: {}",
                        Address::from(data)
                    )
                }
            }
        }

        Ok(accounts)
    }

    fn update(
        &self,
        addr: &Address,
        name: Option<String>,
        desc: Option<String>,
    ) -> Result<(), KeystoreError> {
        let (_, mut kf) = self.search_by_address(addr)?;

        if name.is_some() {
            kf.name = name;
        };

        if desc.is_some() {
            kf.description = desc;
        };

        self.put(&kf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_split() {
        let db_item =
            r#"UTC--2017-03-17T10-52-08.229Z--0047201aed0b69875b24b614dda0270bcd9f11cc<|>{
          "version": 3,
          "id": "f7ab2bfa-e336-4f45-a31f-beb3dd0689f3",
          "name":"test<|><\\\|>"
          "description":"descr<|><\\\|>"
          "address": "0047201aed0b69875b24b614dda0270bcd9f11cc",
          "crypto": {
            "ciphertext": "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1",
            "cipherparams": {
              "iv": "9df1649dd1c50f2153917e3b9e7164e9"
            },
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": {
              "dklen": 32,
              "salt": "fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4",
              "n": 1024,
              "r": 8,
              "p": 1
            },
            "mac": "9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5"
          }
        }"#;

        let (filename, json) = DbStorage::split(&db_item).unwrap();

        assert_eq!(
            filename,
            "UTC--2017-03-17T10-52-08.229Z--0047201aed0b69875b24b614dda0270bcd9f11cc"
        );
        assert_eq!(
            json,
            r#"{
          "version": 3,
          "id": "f7ab2bfa-e336-4f45-a31f-beb3dd0689f3",
          "name":"test<|><\\\|>"
          "description":"descr<|><\\\|>"
          "address": "0047201aed0b69875b24b614dda0270bcd9f11cc",
          "crypto": {
            "ciphertext": "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1",
            "cipherparams": {
              "iv": "9df1649dd1c50f2153917e3b9e7164e9"
            },
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": {
              "dklen": 32,
              "salt": "fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4",
              "n": 1024,
              "r": 8,
              "p": 1
            },
            "mac": "9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5"
          }
        }"#
        )
    }
}
