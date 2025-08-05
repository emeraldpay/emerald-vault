/*
Copyright 2019 ETCDEV GmbH
Copyright 2020 EmeraldPay, Inc

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
//! # Mnemonic sentence generation errors

use std::{error, fmt, io};

/// `Mnemonic` generation errors
#[derive(Debug)]
pub enum Error {
    /// Mnemonic sentence generation error
    MnemonicError(String),

    /// BIP32 key generation error
    KeyGenerationError(String),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::MnemonicError(err.to_string())
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Error::MnemonicError(err.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::MnemonicError(ref str) => write!(f, "Mnemonic generation error: {}", str),
            Error::KeyGenerationError(ref str) => write!(f, "BIP32 generation error: {}", str),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Mnemonic generation error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}
