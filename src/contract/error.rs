use ethabi;
use std::{error, fmt};

/// Contract Service Errors
#[derive(Debug, Clone)]
pub enum Error {
    /// IO Error
    IO(String),

    /// Invalid Contract
    InvalidContract(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IO(ref str) => write!(f, "IO error: {}", str),
            Error::InvalidContract(ref str) => write!(f, "Invalid constract: {}", str),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Contract error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
