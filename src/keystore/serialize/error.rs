//! # Serialize keystore files (UTC / JSON) module errors

use std::{error, fmt};

/// Keystore file serialize errors
#[derive(Debug)]
pub enum Error {
    /// An unsupported version
    UnsupportedVersion(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnsupportedVersion(ver) => {
                write!(f, "Unsupported keystore file version: {}", ver)
            }
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Keystore file serialize error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
