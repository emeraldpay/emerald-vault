/*
Copyright 2019 ETCDEV GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//! # Contracts utils

use crate::contract::Error;
use crate::core::Address;
use glob::glob;
use serde_json;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Contracts Service
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractStorage {
    dir: PathBuf,
}

impl ContractStorage {
    /// Initialize new contracts service for a dir
    pub fn new(dir: PathBuf) -> ContractStorage {
        ContractStorage { dir }
    }

    /// Validate contract structure
    pub fn validate(&self, contract: &serde_json::Value) -> Result<(), Error> {
        if !contract.is_object() {
            return Err(Error::InvalidContract("Invalid data format".to_string()));
        }
        let addr = match contract.get("address") {
            Some(addr) => addr,
            None => return Err(Error::InvalidContract("Missing address".to_string())),
        };
        if !addr.is_string() {
            return Err(Error::InvalidContract("Invalid address format".to_string()));
        }
        match addr.as_str().unwrap().parse::<Address>() {
            Ok(_) => {}
            Err(_) => return Err(Error::InvalidContract("Can't parse address".to_string())),
        }
        Ok(())
    }

    /// Add new contract to storage
    pub fn add(&self, contract: &serde_json::Value) -> Result<(), Error> {
        self.validate(contract)?;
        let addr = contract
            .get("address")
            .expect("Expect address for a contract")
            .as_str()
            .expect("Expect address be convertible to a string");

        let mut filename: PathBuf = self.dir.clone();
        filename.push(format!("{}.json", addr));

        let mut f = File::create(filename.as_path())?;
        match serde_json::to_writer_pretty(&mut f, contract) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::IO(format!(
                "Can't write contract for address {}",
                addr
            ))),
        }
    }

    /// List all available contracts
    pub fn list(&self) -> Vec<serde_json::Value> {
        let files = glob(&format!("{}/*.json", &self.dir.to_str().unwrap())).unwrap();

        files
            .filter(|x| x.is_ok())
            .map(|x| ContractStorage::read_json(x.unwrap().as_path()))
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect()
    }

    fn read_json(path: &Path) -> Result<serde_json::Value, Error> {
        match File::open(path) {
            Ok(f) => serde_json::from_reader(f)
                .or_else(|_| Err(Error::IO("Can't read contract file".to_string()))),
            Err(_) => Err(Error::IO("Can't open contract file".to_string())),
        }
    }
}
