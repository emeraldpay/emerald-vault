//! # Addressbook utils

use super::core::Address;
use glob::glob;
use serde_json;
use std::fs::File;
use std::fs::remove_file;
use std::path::{Path, PathBuf};

/// Addressbook Service
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addressbook {
    dir: PathBuf,
}

/// Addressbook Errors
#[derive(Debug, Clone)]
pub enum AddressbookError {
    /// IO Error
    IO,

    /// Invalid Address
    InvalidAddress,
}

impl Addressbook {
    /// Initialize new addressbook service for a dir
    pub fn new(dir: PathBuf) -> Addressbook {
        Addressbook { dir: dir }
    }

    fn read_json(path: &Path) -> Result<serde_json::Value, AddressbookError> {
        match File::open(path) {
            Ok(f) => serde_json::from_reader(f).or(Err(AddressbookError::IO)),
            Err(_) => Err(AddressbookError::IO),
        }
    }

    /// List all entries in the addressbook
    pub fn list(&self) -> Vec<serde_json::Value> {
        let files = glob(&format!("{}/*.json", &self.dir.to_str().unwrap())).unwrap();

        files
            .filter(|x| x.is_ok())
            .map(|x| Addressbook::read_json(x.unwrap().as_path()))
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect()
    }

    /// Validate addressbook entry structure
    pub fn validate(&self, entry: &serde_json::Value) -> Result<(), AddressbookError> {
        if !entry.is_object() {
            return Err(AddressbookError::InvalidAddress);
        }
        let addr = match entry.get("id") {
            Some(addr) => addr,
            None => return Err(AddressbookError::InvalidAddress),
        };
        if !addr.is_string() {
            return Err(AddressbookError::InvalidAddress);
        }
        match addr.as_str().unwrap().parse::<Address>() {
            Ok(_) => {}
            Err(_) => return Err(AddressbookError::InvalidAddress),
        }
        Ok(())
    }

    /// Add new address entry to addressbook storage
    pub fn add(&self, entry: &serde_json::Value) -> Result<(), AddressbookError> {
        self.validate(entry)?;
        let addr = entry
            .get("id")
            .expect("Expect id for addressbook entry")
            .as_str()
            .expect("Expect id be convertible to a string");
        let mut filename: PathBuf = self.dir.clone();
        filename.push(format!("{}.json", addr));
        let mut f = File::create(filename.as_path()).unwrap();
        match serde_json::to_writer_pretty(&mut f, entry) {
            Ok(_) => Ok(()),
            Err(_) => Err(AddressbookError::IO),
        }
    }

    /// Edit address entry in addressbook storage (address cannot change)
    pub fn edit(&self, entry: &serde_json::Value) -> Result<(), AddressbookError> {
        self.validate(entry)?;
        let addr = entry
            .get("id")
            .expect("Expect id for addressbook entry")
            .as_str()
            .expect("Expect id be convertible to a string");
        let mut filename: PathBuf = self.dir.clone();
        filename.push(format!("{}.json", addr));
        let mut f = File::create(filename.as_path()).unwrap();
        match serde_json::to_writer_pretty(&mut f, entry) {
            Ok(_) => Ok(()),
            Err(_) => Err(AddressbookError::IO),
        }
    }

    /// Edit address entry in addressbook storage (address cannot change)
    pub fn delete(&self, entry: &serde_json::Value) -> Result<(), AddressbookError> {
        let addr = entry
            .as_str()
            .expect("Expect id be convertible to a string");
        let mut filename: PathBuf = self.dir.clone();
        filename.push(format!("{}.json", addr));
        match remove_file(filename) {
            Ok(_) => Ok(()),
            Err(_) => Err(AddressbookError::IO),
        }
    }
}
