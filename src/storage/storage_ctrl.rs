use super::keyfile::KeyStorageError;
use super::KeyfileStorage;
use std::collections::HashMap;

///
pub struct StorageController {
    storages: HashMap<String, Box<KeyfileStorage>>,
}

impl StorageController {
    ///
    pub fn new() -> StorageController {
        StorageController { storages: HashMap::new() }
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
    pub fn insert(&self, chain: &self, storage: Box<KeyfileStorage>) {
        self.storages.insert(chain, storage)
    }
}
