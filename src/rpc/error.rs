//! # JSON RPC module errors

use jsonrpc_core;
use reqwest;
use std::{error, fmt};

/// JSON RPC errors
#[derive(Debug)]
pub enum Error {
    /// Http client error
    HttpClient(reqwest::Error),
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::HttpClient(err)
    }
}

impl Into<jsonrpc_core::Error> for Error {
    fn into(self) -> jsonrpc_core::Error {
        jsonrpc_core::Error::internal_error()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::HttpClient(ref err) => write!(f, "HTTP client error: {}", err),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "JSON RPC errors"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::HttpClient(ref err) => Some(err),
            //_ => None,
        }
    }
}
