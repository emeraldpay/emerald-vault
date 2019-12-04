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
use super::addressbook::AddressbookStorage;
use super::keyfile::KeystoreError;
use super::super::core::chains::EthereumChainId;
use super::{
    build_addressbook_storage, build_keyfile_storage, build_path,
    KeyfileStorage,
};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

/// Controller to switch storage according to specified chain
pub struct StorageController {
    keyfile_storages: HashMap<String, Box<dyn KeyfileStorage>>,
    addressbook_storages: HashMap<String, Box<AddressbookStorage>>,
}

impl StorageController {
    /// Create new `StorageController`
    /// with a subfolders for
    pub fn new<P: AsRef<Path>>(base_path: P) -> Result<StorageController, KeystoreError> {
        let mut st = StorageController::default();
        for id in EthereumChainId::get_all_paths().iter() {
            st.keyfile_storages.insert(
                id.to_string(),
                build_keyfile_storage(build_path(base_path.as_ref(), id, "keystore"))?,
            );
            st.addressbook_storages.insert(
                id.to_string(),
                build_addressbook_storage(build_path(base_path.as_ref(), id, "addressbook"))?,
            );
        }

        Ok(st)
    }

    /// Get `KeyFile` storage for specified chain
    pub fn get_keystore(&self, chain: &str) -> Result<&Box<dyn KeyfileStorage>, KeystoreError> {
        match self.keyfile_storages.get(EthereumChainId::from_str(chain).unwrap().get_path_element().as_str()) {
            Some(st) => Ok(st),
            None => Err(KeystoreError::StorageError(format!(
                "No storage for: {}",
                chain
            ))),
        }
    }

    /// Get `Addressbook` storage for specified chain
    pub fn get_addressbook(&self, chain: &str) -> Result<&Box<AddressbookStorage>, KeystoreError> {
        match self.addressbook_storages.get(EthereumChainId::from_str(chain).unwrap().get_path_element().as_str()) {
            Some(st) => Ok(st),
            None => Err(KeystoreError::StorageError(format!(
                "No storage for: {}",
                chain
            ))),
        }
    }
}

impl Default for StorageController {
    fn default() -> Self {
        StorageController {
            keyfile_storages: HashMap::new(),
            addressbook_storages: HashMap::new(),
        }
    }
}
