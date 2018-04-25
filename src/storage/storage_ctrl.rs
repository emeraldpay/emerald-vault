use super::addressbook::AddressbookStorage;
use super::contracts::ContractStorage;
use super::keyfile::KeystoreError;
use super::{build_addressbook_storage, build_contract_storage, build_keyfile_storage, build_path,
            KeyfileStorage};
use std::collections::HashMap;
use std::path::Path;

/// Controller to switch storage according to specified chain
pub struct StorageController {
    keyfile_storages: HashMap<String, Box<KeyfileStorage>>,
    contract_storages: HashMap<String, Box<ContractStorage>>,
    addressbook_storages: HashMap<String, Box<AddressbookStorage>>,
}

impl StorageController {
    /// Create new `StorageController`
    pub fn new<P: AsRef<Path>>(base_path: P) -> Result<StorageController, KeystoreError> {
        let mut st = StorageController::default();

        for id in &["mainnet", "morden"] {
            st.keyfile_storages.insert(
                id.to_string(),
                build_keyfile_storage(build_path(base_path.as_ref(), id, "keystore"))?,
            );
            st.contract_storages.insert(
                id.to_string(),
                build_contract_storage(build_path(base_path.as_ref(), id, "contracts"))?,
            );
            st.addressbook_storages.insert(
                id.to_string(),
                build_addressbook_storage(build_path(base_path.as_ref(), id, "addressbook"))?,
            );
        }

        Ok(st)
    }

    /// Get `KeyFile` storage for specified chain
    pub fn get_keystore(&self, chain: &str) -> Result<&Box<KeyfileStorage>, KeystoreError> {
        match self.keyfile_storages.get(chain) {
            Some(st) => Ok(st),
            None => Err(KeystoreError::StorageError(format!(
                "No storage for: {}",
                chain
            ))),
        }
    }

    /// Get `Contract` storage for specified chain
    pub fn get_contracts(&self, chain: &str) -> Result<&Box<ContractStorage>, KeystoreError> {
        match self.contract_storages.get(chain) {
            Some(st) => Ok(st),
            None => Err(KeystoreError::StorageError(format!(
                "No storage for: {}",
                chain
            ))),
        }
    }

    /// Get `Addressbook` storage for specified chain
    pub fn get_addressbook(&self, chain: &str) -> Result<&Box<AddressbookStorage>, KeystoreError> {
        match self.addressbook_storages.get(chain) {
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
            contract_storages: HashMap::new(),
            addressbook_storages: HashMap::new(),
        }
    }
}
