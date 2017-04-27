//! # Serialize keystore files (UTC / JSON) module errors

use rustc_serialize::json;
use std::{error, fmt, io};

/// Keystore file serialize errors
#[derive(Debug)]
pub enum Error {
    /// An unsupported version
    UnsupportedVersion(u8),
    /// Can't proceed keyfile search by address
    InvalidKeyfileSearch(String),
    /// Can't decode to `Keyfile`
    InvalidKeyfileDecoding(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnsupportedVersion(ver) => {
                write!(f, "Unsupported keystore file version: {}", ver)
            }
            Error::InvalidKeyfileSearch(ref str) => {
                write!(f, "Can't proceed Keyfile search: {}", str)
            }
            Error::InvalidKeyfileDecoding(ref str) => write!(f, "Can't decode Keyfile: {}", str),
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

impl From<json::DecoderError> for Error {
    fn from(err: json::DecoderError) -> Self {
        Error::InvalidKeyfileDecoding(err.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::InvalidKeyfileSearch(err.to_string())
    }
}
