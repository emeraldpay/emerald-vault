//! # Core domain logic module errors

use ethabi;
use hex;
use secp256k1;
use std::{error, fmt};

/// Core domain logic errors
#[derive(Debug)]
pub enum Error {
    /// Invalid ABI
    InvalidABI(String),

    /// Invalid ABI Token
    InvalidABIToken(ethabi::token::Error),

    /// An invalid length
    InvalidLength(usize),

    /// An unexpected hexadecimal prefix (should be '0x')
    InvalidHexLength(String),

    /// An unexpected hexadecimal encoding
    UnexpectedHexEncoding(hex::FromHexError),

    /// ECDSA crypto error
    EcdsaCrypto(secp256k1::Error),
}

impl From<ethabi::Error> for Error {
    fn from(err: ethabi::Error) -> Self {
        Error::InvalidABI(format!("Invalid ABI {:?}", err))
    }
}

impl From<ethabi::spec::Error> for Error {
    fn from(err: ethabi::spec::Error) -> Self {
        Error::InvalidABI(format!("Invalid ABI Spec {:?}", err))
    }
}

impl From<ethabi::token::Error> for Error {
    fn from(err: ethabi::token::Error) -> Self {
        Error::InvalidABIToken(err)
    }
}

impl From<ethabi::spec::param_type::Error> for Error {
    fn from(err: ethabi::spec::param_type::Error) -> Self {
        Error::InvalidABI(format!("Invalid ABI Param {:?}", err))
    }
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
            Error::InvalidABI(ref str) => write!(f, "Invalid ABI: {}", str),
            Error::InvalidABIToken(ref err) => write!(f, "Invalid ABI Token: {:?}", err),
            Error::InvalidLength(len) => write!(f, "Invalid length: {}", len),
            Error::InvalidHexLength(ref str) => write!(f, "Invalid hex data length: {}", str),
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
