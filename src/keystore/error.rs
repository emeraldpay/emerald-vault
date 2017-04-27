//! # Keystore files (UTC / JSON) module errors

use rustc_serialize::json;
use std::{error, fmt, io};

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
    ///
    FileCreation,
    ///
    InvalidEncoding,
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
            Error::FileCreation => write!(f, "Can't create file for KeyFile"),
            Error::InvalidEncoding => write!(f, "Can't encode KeyFile"),
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

impl From<json::EncoderError> for Error {
    fn from(_: json::EncoderError) -> Self {
        Error::InvalidEncoding
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::FileCreation
    }
}
