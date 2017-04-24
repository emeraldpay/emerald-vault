//! # Keystore files (UTC / JSON) module errors

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
            Error::FailedMacValidation => f.write_str("Message authentication code failed"),
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
