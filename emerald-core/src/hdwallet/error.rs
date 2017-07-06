//! # HDWallet Keystore files (UTC / JSON) module errors

use super::core;
use std::{error, fmt};

/// HDWallet Keystore file errors
#[derive(Debug)]
pub enum Error {
    /// An unsupported cipher
    HDWalletError(String),
}

impl From<core::Error> for Error {
    fn from(err: core::Error) -> Self {
        Error::CoreFault(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::HDWalletError(ref str) => write!(f, "HD Wallet error: {}", str),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "HD Wallet Keystore file error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::HDWalletError(ref err) => Some(err),
            _ => None,
        }
    }
}
