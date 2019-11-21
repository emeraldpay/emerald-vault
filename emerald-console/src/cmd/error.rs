//! # Errors for command executor

use crate::emerald::storage::KeystoreError;
use crate::emerald::{self, keystore};
use hex;
use serde_json;
use std::net::AddrParseError;
use std::num;
use std::{error, fmt, io, str, string};

macro_rules! from_err {
    ($x:ty) => {
        impl From<$x> for Error {
            fn from(err: $x) -> Self {
                Error::ExecError(err.to_string())
            }
        }
    };
}

///
#[derive(Debug)]
pub enum Error {
    /// Command execution error
    ExecError(String),
}

impl From<AddrParseError> for Error {
    fn from(err: AddrParseError) -> Self {
        Error::ExecError(format!("Can't parse host/port args: {}", err.to_string()))
    }
}

from_err!(io::Error);
from_err!(KeystoreError);
from_err!(string::ParseError);
from_err!(keystore::Error);
from_err!(keystore::SerializeError);
from_err!(num::ParseIntError);
from_err!(hex::FromHexError);
from_err!(emerald::Error);
from_err!(emerald::mnemonic::Error);
from_err!(serde_json::Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ExecError(ref str) => write!(f, "Command execution error: {}", str),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Command execution error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            _ => None,
        }
    }
}
