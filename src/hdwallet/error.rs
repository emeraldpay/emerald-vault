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
//! # `HDWallet` Keystore files (UTC / JSON) module errors

use bitcoin::util::bip32;
use crate::core;
use std::{error, fmt, io};

/// `HDWallet` Keystore file errors
#[derive(Debug)]
pub enum Error {
    /// An unsupported cipher
    HDWalletError(String),

    /// Error from HID communication
    CommError(String),
}

impl From<core::Error> for Error {
    fn from(err: core::Error) -> Self {
        Error::HDWalletError(err.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::HDWalletError(err.to_string())
    }
}

impl<'a> From<&'a str> for Error {
    fn from(err: &str) -> Self {
        Error::HDWalletError(err.to_string())
    }
}

impl From<bip32::Error> for Error {
    fn from(err: bip32::Error) -> Self {
        Error::HDWalletError(err.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::HDWalletError(ref str) => write!(f, "HD Wallet error: {}", str),
            Error::CommError(ref str) => write!(f, "Communication protocol error: {}", str),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "HD Wallet Keystore file error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
