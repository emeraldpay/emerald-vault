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
//! # Errors for storage of `Addressbook`
use std::{error, fmt};

/// Addressbook Errors
#[derive(Debug, Clone)]
pub enum AddressbookError {
    /// IO Error
    IO(String),

    /// Invalid Address
    InvalidAddress(String),
}

impl fmt::Display for AddressbookError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AddressbookError::IO(ref str) => write!(f, "IO error: {}", str),
            AddressbookError::InvalidAddress(ref str) => write!(f, "Invalid address: {}", str),
        }
    }
}

impl error::Error for AddressbookError {
    fn description(&self) -> &str {
        "Addressbook error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
