//! # Keystore files (UTC / JSON) errors

use std::{error, fmt};

/// Keystore file errors
#[derive(Debug)]
pub enum KeyFileError {
    /// An unsupported cipher
    UnsupportedCipher(String),
    /// An unsupported key derivation function
    UnsupportedKdf(String),
    /// An unsupported pseudo-random function
    UnsupportedPrf(String),
    /// `keccak256_mac` validation failed
    FailedMacValidation,
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyFileError::UnsupportedCipher(ref str) => write!(f, "Unsupported cipher: {}", str),
            KeyFileError::UnsupportedKdf(ref str) => {
                write!(f, "Unsupported key derivation function: {}", str)
            }
            KeyFileError::UnsupportedPrf(ref str) => {
                write!(f, "Unsupported pseudo-random function: {}", str)
            }
            KeyFileError::FailedMacValidation => f.write_str("Message authentication code failed"),
        }
    }
}

impl error::Error for KeyFileError {
    fn description(&self) -> &str {
        "Keystore file error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
