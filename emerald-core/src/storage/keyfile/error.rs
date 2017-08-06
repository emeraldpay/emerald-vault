//! # Errors for storage of `Keyfiles`

use keystore::SerializeError;
use rocksdb;
use rustc_serialize::json;
use std::{error, fmt, io, str};

///
#[derive(Debug)]
pub enum Error {
    ///
    StorageError(String),
    ///
    NotFound(String),
}

impl From<rocksdb::Error> for Error {
    fn from(err: rocksdb::Error) -> Self {
        Error::StorageError(format!("Keyfile storage error: {}", err.to_string()))
    }
}

impl From<json::EncoderError> for Error {
    fn from(err: json::EncoderError) -> Self {
        Error::StorageError(err.to_string())
    }
}


impl From<SerializeError> for Error {
    fn from(err: SerializeError) -> Self {
        Error::StorageError(err.to_string())
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Self {
        Error::StorageError(err.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::StorageError(ref str) => write!(f, "Keyfile storage error: {}", str),
            Error::NotFound(ref str) => write!(f, "Missing Keyfile for address: {}", str),
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
