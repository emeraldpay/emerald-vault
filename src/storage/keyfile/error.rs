//! # Errors for storage of `Keyfiles`

use keystore::SerializeError;
use rocksdb;
use rustc_serialize::json;
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

impl From<json::EncoderError> for KeystoreError {
    fn from(err: json::EncoderError) -> Self {
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
