//! # Contracts utils

use address::Address;
use glob::glob;
use serde_json::{self, Value};
use std::fs::File;
use std::path::{Path, PathBuf};

/// Contracts Service
#[derive(Debug, Clone, PartialEq, Eq)]
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
        files
            .filter(|x| x.is_ok())
            .map(|x| Contracts::read_json(x.unwrap().as_path()))
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect()
    }

    /// Validate contract structure
    pub fn validate(&self, contract: &Value) -> Result<(), ContractError> {
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
        Ok(())
    }

    /// Add new contract to storage
    pub fn add(&self, contract: &Value) -> Result<(), ContractError> {
        self.validate(contract)?;
        let addr = contract
            .get("address")
            .expect("Expect address for a contract")
            .as_str()
            .expect("Expect address be convertible to a string");
        let mut filename: PathBuf = self.dir.clone();
        filename.push(format!("{}.json", addr));
        let mut f = File::create(filename.as_path()).unwrap();
        match serde_json::to_writer_pretty(&mut f, contract) {
            Ok(_) => Ok(()),
            Err(_) => Err(ContractError::IO),
        }
    }
}
