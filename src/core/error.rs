//! # Core domain logic module errors

use rustc_serialize::hex;
use secp256k1;
use std::{error, fmt};

/// Core domain logic errors
#[derive(Debug)]
pub enum Error {
    /// An invalid length
    InvalidLength(usize),
    /// An unexpected hexadecimal prefix (should be '0x')
    UnexpectedHexPrefix(String),
    /// An unexpected hexadecimal encoding
    UnexpectedHexEncoding(hex::FromHexError),
    /// ECDSA crypto error
    EcdsaCrypto(secp256k1::Error),
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::UnexpectedHexEncoding(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Error::EcdsaCrypto(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidLength(len) => write!(f, "Invalid length: {}", len),
            Error::UnexpectedHexPrefix(ref str) => {
                write!(f, "Unexpected hexadecimal prefix (should be '0x'): {}", str)
            }
            Error::UnexpectedHexEncoding(ref err) => {
                write!(f, "Unexpected hexadecimal encoding: {}", err)
            }
            Error::EcdsaCrypto(ref err) => write!(f, "ECDSA crypto error: {}", err),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Core error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::UnexpectedHexEncoding(ref err) => Some(err),
            Error::EcdsaCrypto(ref err) => Some(err),
            _ => None,
        }
    }
}
