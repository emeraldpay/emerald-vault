//! # Errors for storage of `Keyfiles`

use rocksdb;
use std::{error, fmt, io};

pub enum Error {
    ///
    StorageError(String),
}

impl From<rocksdb::Error> for Error {
    fn from(err: Error) -> Self {
        Error::StorageError(format!("Keyfile storage error: {}", err.to_string()))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::StorageError(ref str) => write!(f, "Keyfile storage error: {}", str)
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Keyfile storage error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}