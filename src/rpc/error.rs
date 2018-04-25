//! # JSON RPC module errors

use super::core;
use super::storage;
use contract;
use hdwallet;
use hex;
use jsonrpc_core;
use keystore;
use mnemonic;
use reqwest;
use rustc_serialize;
use serde_json;
use std::{error, fmt, io};

/// JSON RPC errors
#[derive(Debug)]
pub enum Error {
    /// Http client error
    HttpClient(reqwest::Error),
    /// RPC error
    RPC(jsonrpc_core::Error),
    /// Invalid data format
    InvalidDataFormat(String),
    /// Storage error
    StorageError(String),
    /// Storage error
    ContractAbiError(String),
    /// Mnemonic phrase operations error
    MnemonicError(String),
    /// Addressbook operations error
    AddressbookError(String),
}

impl From<storage::addressbook::error::AddressbookError> for Error {
    fn from(err: storage::addressbook::error::AddressbookError) -> Self {
        Error::AddressbookError(err.to_string())
    }
}

impl From<rustc_serialize::json::EncoderError> for Error {
    fn from(err: rustc_serialize::json::EncoderError) -> Self {
        Error::InvalidDataFormat(format!("decoder: {}", err.to_string()))
    }
}

impl From<rustc_serialize::json::DecoderError> for Error {
    fn from(err: rustc_serialize::json::DecoderError) -> Self {
        Error::InvalidDataFormat(format!("decoder: {}", err.to_string()))
    }
}

impl From<keystore::Error> for Error {
    fn from(err: keystore::Error) -> Self {
        Error::InvalidDataFormat(format!("keystore: {}", err.to_string()))
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::InvalidDataFormat(e.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::HttpClient(err)
    }
}

impl From<core::Error> for Error {
    fn from(err: core::Error) -> Self {
        Error::InvalidDataFormat(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::InvalidDataFormat(err.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::InvalidDataFormat(err.to_string())
    }
}

impl From<jsonrpc_core::Error> for Error {
    fn from(err: jsonrpc_core::Error) -> Self {
        Error::RPC(err)
    }
}

impl From<storage::KeystoreError> for Error {
    fn from(err: storage::KeystoreError) -> Self {
        Error::StorageError(err.to_string())
    }
}

impl From<contract::Error> for Error {
    fn from(err: contract::Error) -> Self {
        Error::ContractAbiError(err.to_string())
    }
}

impl From<mnemonic::Error> for Error {
    fn from(err: mnemonic::Error) -> Self {
        Error::MnemonicError(err.to_string())
    }
}

impl From<hdwallet::Error> for Error {
    fn from(err: hdwallet::Error) -> Self {
        Error::MnemonicError(err.to_string())
    }
}

impl Into<jsonrpc_core::Error> for Error {
    fn into(self) -> jsonrpc_core::Error {
        jsonrpc_core::Error::internal_error()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::HttpClient(ref err) => write!(f, "HTTP client error: {}", err),
            Error::RPC(ref err) => write!(f, "RPC error: {:?}", err),
            Error::InvalidDataFormat(ref str) => write!(f, "Invalid data format: {}", str),
            Error::StorageError(ref str) => write!(f, "Keyfile storage error: {}", str),
            Error::ContractAbiError(ref str) => write!(f, "Contract ABI error: {}", str),
            Error::MnemonicError(ref str) => write!(f, "Mnemonic error: {}", str),
            Error::AddressbookError(ref str) => write!(f, "Addressbook error: {}", str),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "JSON RPC errors"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::HttpClient(ref err) => Some(err),
            _ => None,
        }
    }
}
