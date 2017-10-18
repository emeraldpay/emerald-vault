use super::{KeyfileStorage, build_keystore_path, build_storage};
use super::keyfile::KeyStorageError;
use std::collections::HashMap;
use std::path::Path;

///
pub struct StorageController {
    storages: HashMap<String, Box<KeyfileStorage>>,
}

impl StorageController {
    ///
    pub fn new<P: AsRef<Path>>(base_path: P) -> Result<StorageController, KeyStorageError> {
        let mut st = StorageController::default();
        for id in ["mainnet", "testnet"].iter() {
            st.insert(
                id,
                build_storage(build_keystore_path(base_path.as_ref(), id))?,
            );
        }

        Ok(st)
    }

    ///
    pub fn get(&self, chain: &str) -> Result<&Box<KeyfileStorage>, KeyStorageError> {
        match self.storages.get(chain) {
            Some(st) => Ok(st),
            None => Err(KeyStorageError::StorageError(
                format!("No storage for: {}", chain),
            )),
        }
    }

    ///
    pub fn insert(&mut self, chain: &str, storage: Box<KeyfileStorage>) {
        self.storages.insert(chain.to_string(), storage);
    }
}

impl Default for StorageController {
    fn default() -> Self {
        StorageController { storages: HashMap::new() }
    }
}
