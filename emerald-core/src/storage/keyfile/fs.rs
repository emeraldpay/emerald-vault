//! # KeyFile storage within filesystem


use super::KeyfileStorage;
use super::error::Error;
use core::{self, Address};
use hdwallet::HdwalletCrypto;
use keystore::{CIPHER_IV_BYTES, Cipher, CryptoType, KDF_SALT_BYTES, Kdf, KeyFile};
use keystore::{CoreCrypto, Iv, Mac, Salt, decode_str, try_extract_address};
use rustc_serialize::{Encodable, Encoder, json};
use std::ffi::OsStr;
use std::fs::{self, File, read_dir};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use util;
use uuid::Uuid;

/// Filesystem storage for `KeyFiles`
///
pub struct fsStorage {
    /// Parent directory for storage
    base_path: PathBuf,
}


/// Result for searching `KeyFile` in base_path
/// and it subdirectories
///
struct SearchResult {
    /// Path to target `KeyFile`
    path: PathBuf,

    /// Decoded `KeyFile`
    kf: KeyFile,
}

impl fsStorage {
    ///
    pub fn new<P>(dir: P) -> fsStorage
    where
        P: AsRef<Path> + AsRef<OsStr>,
    {
        fsStorage { base_path: PathBuf::from(&dir) }
    }

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

    ///
    fn toogle_visibility(&self, addr: &Address, is_visible: bool) -> Result<(), Error> {
        let mut res = self.search(addr)?;

        res.kf.visible = Some(is_visible);
        self.delete(&res.kf.address)?;
        fsStorage::put_with_name(&res.kf, &res.path)?;

        Ok(())
    }

    fn put_with_name<P: AsRef<Path>>(kf: &KeyFile, path: P) -> Result<(), Error> {
        let json = json::encode(&kf)?;
        let mut file = File::create(&path)?;
        file.write_all(json.as_ref()).ok();

        Ok(())
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

impl KeyfileStorage for fsStorage {
    fn put(&self, kf: &KeyFile) -> Result<(), Error> {
        let name = fsStorage::generate_filename(&kf.uuid.to_string());
        let p: PathBuf = self.base_path.clone();
        let p_ref: &Path = p.as_ref();
        let path = p_ref.join(name);

        fsStorage::put_with_name(&kf, path)
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

    /// Search of `KeyFile` by specified `Address`
    /// Returns set of filepath and `KeyFile`
    ///KeyFile
    /// # Arguments
    ///
    /// * `addr` - a public address
    ///
    fn search_by_address(&self, addr: &Address) -> Result<KeyFile, Error> {
        let res = self.search(addr)?;
        Ok(res.kf)
    }

    /// Lists addresses for `Keystore` files in specified folder.
    /// Can include hidden files if flag set.
    ///
    /// # Arguments
    ///
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
