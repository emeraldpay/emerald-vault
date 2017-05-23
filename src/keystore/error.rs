//! # Keystore files (UTC / JSON) module errors

use super::core;
use std::{error, fmt};

/// Keystore file errors
#[derive(Debug)]
pub enum Error {
    /// An unsupported cipher
    UnsupportedCipher(String),

    /// An unsupported key derivation function
    UnsupportedKdf(String),

    /// An unsupported pseudo-random function
    UnsupportedPrf(String),

    /// `keccak256_mac` field validation failed
    FailedMacValidation,

    /// Core module error wrapper
    CoreFault(core::Error),

    /// Invalid Kdf depth value
    InvalidKdfDepth(String),
}

impl From<core::Error> for Error {
    fn from(err: core::Error) -> Self {
        Error::CoreFault(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnsupportedCipher(ref str) => write!(f, "Unsupported cipher: {}", str),
            Error::UnsupportedKdf(ref str) => {
                write!(f, "Unsupported key derivation function: {}", str)
            }
            Error::UnsupportedPrf(ref str) => {
                write!(f, "Unsupported pseudo-random function: {}", str)
            }
            Error::FailedMacValidation => write!(f, "Message authentication code failed"),
            Error::CoreFault(ref err) => f.write_str(&err.to_string()),
            Error::InvalidKdfDepth(ref str) => write!(f, "Invalid security level: {}", str),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Keystore file error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::CoreFault(ref err) => Some(err),
            _ => None,
        }
    }
}
