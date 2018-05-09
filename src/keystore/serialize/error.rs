//! # Serialize keystore files (UTC / JSON) module errors

use hdwallet;
use rpc;
use serde_json;

use std::{error, fmt, io};

/// Keystore file serialize errors
#[derive(Debug)]
pub enum Error {
    /// An unsupported version
    UnsupportedVersion(u8),

    /// IO errors
    IO(io::Error),

    /// Invalid `Keyfile` decoding
    InvalidDecoding(serde_json::Error),

    /// Invalid `Keyfile` encoding
    InvalidEncoding(serde_json::Error),

    /// `KeyFile` wasn't found
    NotFound,

    /// `Keyfile` crypto section parsing
    InvalidCrypto(String),
}

impl From<Error> for rpc::Error {
    fn from(_err: Error) -> Self {
        rpc::Error::InvalidDataFormat("Invalid serialization for keystore".to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::InvalidEncoding(err)
    }
}

//impl From<serde_json::Error> for Error {
//    fn from(err: serde_json::Error) -> Self {
//        Error::InvalidDecoding(err)
//    }
//}

impl From<hdwallet::Error> for Error {
    fn from(err: hdwallet::Error) -> Self {
        Error::InvalidCrypto(err.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnsupportedVersion(v) => write!(f, "Unsupported keystore file version: {}", v),
            Error::IO(ref err) => write!(f, "Keystore file IO error: {}", err),
            Error::InvalidDecoding(ref err) => write!(f, "Invalid keystore file decoding: {}", err),
            Error::InvalidEncoding(ref err) => write!(f, "Invalid keystore file encoding: {}", err),
            Error::NotFound => f.write_str("Required keystore file wasn't found"),
            Error::InvalidCrypto(ref str) => {
                f.write_str(&format!("Can't parse `crypto` section for. {}", str))
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
