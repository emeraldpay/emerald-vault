//! # Addressbook utils
pub mod error;

use self::error::AddressbookError;
use core::Address;
use glob::glob;
use serde_json;
use std::fs::remove_file;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Addressbook Service
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressbookStorage {
    dir: PathBuf,
}

impl AddressbookStorage {
    /// Initialize new addressbook service for a dir
    pub fn new(dir: PathBuf) -> AddressbookStorage {
        AddressbookStorage { dir }
    }

    /// Read addressbook files
    pub fn read_json(path: &Path) -> Result<serde_json::Value, AddressbookError> {
        match File::open(path) {
            Ok(f) => serde_json::from_reader(f)
                .or_else(|_| Err(AddressbookError::IO("Can't read address file".to_string()))),
            Err(_) => Err(AddressbookError::IO("Can't open adress file".to_string())),
        }
    }

    /// List all entries in the addressbook
    pub fn list(&self) -> Vec<serde_json::Value> {
        let files = glob(&format!("{}/*.json", &self.dir.to_str().unwrap())).unwrap();

        files
            .filter(|x| x.is_ok())
            .map(|x| AddressbookStorage::read_json(x.unwrap().as_path()))
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect()
    }

    /// Validate addressbook entry structure
    pub fn validate(&self, entry: &serde_json::Value) -> Result<(), AddressbookError> {
        if !entry.is_object() {
            return Err(AddressbookError::InvalidAddress(
                "Invalid data format".to_string(),
            ));
        }
        let addr = match entry.get("address") {
            Some(addr) => addr,
            None => {
                return Err(AddressbookError::InvalidAddress(
                    "Missing address".to_string(),
                ))
            }
        };
        if !addr.is_string() {
            return Err(AddressbookError::InvalidAddress(
                "Invalid address format".to_string(),
            ));
        }
        match addr.as_str().unwrap().parse::<Address>() {
            Ok(_) => {}
            Err(_) => {
                return Err(AddressbookError::InvalidAddress(
                    "Can't parse address".to_string(),
                ))
            }
        }
        Ok(())
    }

    /// Add new address entry to addressbook storage
    pub fn add(&self, entry: &serde_json::Value) -> Result<(), AddressbookError> {
        self.validate(entry)?;
        let addr = entry
            .get("address")
            .expect("Expect address for addressbook entry")
            .as_str()
            .expect("Expect address be convertible to a string");
        let mut filename: PathBuf = self.dir.clone();
        filename.push(format!("{}.json", addr));
        let mut f = File::create(filename.as_path()).unwrap();
        match serde_json::to_writer_pretty(&mut f, entry) {
            Ok(_) => Ok(()),
            Err(_) => Err(AddressbookError::IO(format!(
                "Can't write address {}",
                addr
            ))),
        }
    }

    /// Edit address entry in addressbook storage (address cannot change)
    pub fn edit(&self, entry: &serde_json::Value) -> Result<(), AddressbookError> {
        self.validate(entry)?;
        let addr = entry
            .get("address")
            .expect("Expect id for addressbook entry")
            .as_str()
            .expect("Expect id be convertible to a string");
        let mut filename: PathBuf = self.dir.clone();
        filename.push(format!("{}.json", addr));
        let mut f = File::create(filename.as_path()).unwrap();
        match serde_json::to_writer_pretty(&mut f, entry) {
            Ok(_) => Ok(()),
            Err(_) => Err(AddressbookError::IO(format!(
                "Can't write address {}",
                addr
            ))),
        }
    }

    /// Delete address entry in addressbook storage (address cannot change)
    pub fn delete(&self, entry: &serde_json::Value) -> Result<(), AddressbookError> {
        let addr = entry
            .as_str()
            .expect("Expect address be convertible to a string");
        let mut filename: PathBuf = self.dir.clone();
        filename.push(format!("{}.json", addr));
        match remove_file(filename) {
            Ok(_) => Ok(()),
            Err(_) => Err(AddressbookError::IO(format!(
                "Can't delete file for address {}",
                addr
            ))),
        }
    }
}
