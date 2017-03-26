#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#![deny(clippy, clippy_pedantic)]
#![allow(missing_docs_in_private_items, unknown_lints)]

extern crate serde;
extern crate serde_json;
extern crate glob;
extern crate futures;

use self::glob::glob;
use self::serde_json::Value;
pub use keystore::Address;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Contracts Service
pub struct Contracts {
    dir: PathBuf,
}

/// Contract Service Errors
#[derive(Debug, Clone)]
pub enum ContractError {
    /// IO Error
    IO,
    /// Invalid Contract
    InvalidContract,
}

impl Contracts {
    /// Initialize new contracts service for a dir
    pub fn new(dir: PathBuf) -> Contracts {
        Contracts { dir: dir }
    }

    fn read_json(path: &Path) -> Result<Value, ContractError> {
        match File::open(path) {
            Ok(f) => serde_json::from_reader(f).or(Err(ContractError::IO)),
            Err(_) => Err(ContractError::IO),
        }
    }

    /// List all available contracts
    pub fn list(&self) -> Vec<Value> {
        let files = glob(&format!("{}/*.json", &self.dir.to_str().unwrap())).unwrap();
        files.filter(|x| x.is_ok())
            .map(|x| Contracts::read_json(x.unwrap().as_path()))
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect()
    }

    /// Validate contract structure
    pub fn is_valid(&self, contract: &Value) -> Result<(), ContractError> {
        if !contract.is_object() {
            return Err(ContractError::InvalidContract);
        }
        let addr = match contract.get("address") {
            Some(addr) => addr,
            None => return Err(ContractError::InvalidContract),
        };
        if !addr.is_string() {
            return Err(ContractError::InvalidContract);
        }
        match addr.as_str().unwrap().parse::<Address>() {
            Ok(_) => {}
            Err(_) => return Err(ContractError::InvalidContract),
        }
        return Ok(());
    }

    /// Add new contract to storage
    pub fn add(&self, contract: &Value) -> Result<(), ContractError> {
        self.is_valid(contract)?;
        let addr = contract.get("address")
            .unwrap()
            .as_str()
            .unwrap();
        let filename = format!("{}/{}.json", &self.dir.to_str().unwrap(), addr);
        let mut f = File::create(filename).unwrap();
        match serde_json::to_writer_pretty(&mut f, contract) {
            Ok(_) => Ok(()),
            Err(_) => Err(ContractError::IO),
        }
    }
}
