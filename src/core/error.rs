/*
Copyright 2019 ETCDEV GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//! # Core domain logic module errors

use hex;
use secp256k1;
use std::{error, fmt};

/// Core domain logic errors
#[derive(Debug)]
#[deprecated]
pub enum Error {
    /// An invalid length
    InvalidLength(usize),

    /// An unexpected hexadecimal prefix (should be '0x')
    InvalidHexLength(String),

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
