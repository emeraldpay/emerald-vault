//! # JSON RPC module errors

use super::core;
use jsonrpc_core;
use keystore;
use reqwest;
use rustc_serialize::{self, hex};
use serde_json;
use std::{error, fmt};

/// JSON RPC errors
#[derive(Debug)]
pub enum Error {
    /// Http client error
    HttpClient(reqwest::Error),
    /// RPC error
    RPC(jsonrpc_core::Error),
    /// Invalid data format
    InvalidDataFormat(String),
}

impl From<rustc_serialize::json::EncoderError> for Error {
    fn from(err: rustc_serialize::json::EncoderError) -> Self {
        Error::InvalidDataFormat("encoder error".to_string())
    }
}

impl From<rustc_serialize::json::DecoderError> for Error {
    fn from(err: rustc_serialize::json::DecoderError) -> Self {
        Error::InvalidDataFormat("decoder error".to_string())
    }
}

impl From<keystore::Error> for Error {
    fn from(err: keystore::Error) -> Self {
        Error::InvalidDataFormat("keystore error".to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::HttpClient(err)
    }
}

impl From<core::Error> for Error {
    fn from(err: core::Error) -> Self {
        Error::InvalidDataFormat(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::InvalidDataFormat(err.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::InvalidDataFormat(err.to_string())
    }
}

impl From<jsonrpc_core::Error> for Error {
    fn from(err: jsonrpc_core::Error) -> Self {
        Error::RPC(err)
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
            Error::RPC(ref err) => write!(f, "RPC error: {:?}", err),
            Error::InvalidDataFormat(ref str) => write!(f, "Invalid data format: {}", str),
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
            _ => None,
        }
    }
}
