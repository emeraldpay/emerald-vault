//! # Serialize keystore files (UTC / JSON) module errors

use rustc_serialize::json;
use std::{error, fmt, io};

/// Keystore file serialize errors
#[derive(Debug)]
pub enum Error {
    /// An unsupported version
    UnsupportedVersion(u8),
    /// Can't proceed keyfile search by address
    KeyfileCreation(String),
    /// Can't decode to `Keyfile`
    InvalidKeyfileDecoding(String),
    /// Can't endoce to `Keyfile`
    InvalidKeyfileEncoding(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnsupportedVersion(ver) => {
                write!(f, "Unsupported keystore file version: {}", ver)
            }
            Error::KeyfileCreation(ref str) => write!(f, "Can't create file for Keyfile: {}", str),
            Error::InvalidKeyfileDecoding(ref str) => write!(f, "Can't decode Keyfile: {}", str),
            Error::InvalidKeyfileEncoding(ref str) => write!(f, "Can't decode Keyfile: {}", str),
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
        Error::KeyfileCreation(err.to_string())
    }
}

impl From<json::EncoderError> for Error {
    fn from(err: json::EncoderError) -> Self {
        Error::InvalidKeyfileEncoding(err.to_string())
    }
}
