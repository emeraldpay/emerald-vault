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
    /// Invalid format of `PrivateKey`
    InvalidPrivateKey,
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
            Error::InvalidPrivateKey => write!(f, "Invalid format of private key"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Keystore file error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}

impl From<core::Error> for Error {
    fn from(_: core::Error) -> Self {
        Error::InvalidPrivateKey
    }
}
