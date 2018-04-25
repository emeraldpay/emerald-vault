//! # Errors for storage of `Addressbook`
use std::{error, fmt};

/// Addressbook Errors
#[derive(Debug, Clone)]
pub enum AddressbookError {
    /// IO Error
    IO(String),

    /// Invalid Address
    InvalidAddress(String),
}

impl fmt::Display for AddressbookError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AddressbookError::IO(ref str) => write!(f, "IO error: {}", str),
            AddressbookError::InvalidAddress(ref str) => write!(f, "Invalid address: {}", str),
        }
    }
}

impl error::Error for AddressbookError {
    fn description(&self) -> &str {
        "Addressbook error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
