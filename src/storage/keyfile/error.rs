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
//! # Errors for storage of `Keyfiles`

use crate::keystore::SerializeError;
use crate::rocksdb;
use serde_json;

use std::{error, fmt, io, str};

///
#[derive(Debug)]
pub enum KeystoreError {
    /// General storage error
    StorageError(String),

    /// `KeyFile` not found
    NotFound(String),
}

impl From<rocksdb::Error> for KeystoreError {
    fn from(err: rocksdb::Error) -> Self {
        KeystoreError::StorageError(format!("Keyfile storage error: {}", err.to_string()))
    }
}

impl From<serde_json::Error> for KeystoreError {
    fn from(err: serde_json::Error) -> Self {
        KeystoreError::StorageError(err.to_string())
    }
}

impl From<SerializeError> for KeystoreError {
    fn from(err: SerializeError) -> Self {
        KeystoreError::StorageError(err.to_string())
    }
}

impl From<str::Utf8Error> for KeystoreError {
    fn from(err: str::Utf8Error) -> Self {
        KeystoreError::StorageError(err.to_string())
    }
}

impl From<io::Error> for KeystoreError {
    fn from(err: io::Error) -> Self {
        KeystoreError::StorageError(err.to_string())
    }
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeystoreError::StorageError(ref str) => write!(f, "KeyFile storage error: {}", str),
            KeystoreError::NotFound(ref str) => write!(f, "Missing KeyFile for address: {}", str),
        }
    }
}

impl error::Error for KeystoreError {
    fn description(&self) -> &str {
        "KeyFile storage error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
