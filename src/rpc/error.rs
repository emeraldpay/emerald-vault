//! # JSON RPC module errors

use std::{error, fmt};

/// JSON RPC errors
#[derive(Debug)]
pub enum Error {
}

impl fmt::Display for Error {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "JSON RPC errors"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
