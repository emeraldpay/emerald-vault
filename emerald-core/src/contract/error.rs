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
use ethabi;
use std::string::ToString;
use std::{error, fmt, io};

/// Contract Service Errors
#[derive(Debug, Clone)]
pub enum Error {
    /// IO Error
    IO(String),

    /// Invalid Contract
    InvalidContract(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IO(ref str) => write!(f, "IO error: {}", str),
            Error::InvalidContract(ref str) => write!(f, "Invalid contract: {}", str),
        }
    }
}

impl From<ethabi::Error> for Error {
    fn from(_: ethabi::Error) -> Self {
        Error::InvalidContract("ethabi error".to_string())
    }
}

impl From<ethabi::spec::Error> for Error {
    fn from(_: ethabi::spec::Error) -> Self {
        Error::InvalidContract("ethabi spec error".to_string())
    }
}

impl From<ethabi::spec::param_type::Error> for Error {
    fn from(_: ethabi::spec::param_type::Error) -> Self {
        Error::InvalidContract("ethabi param error".to_string())
    }
}

impl From<ethabi::token::Error> for Error {
    fn from(_: ethabi::token::Error) -> Self {
        Error::InvalidContract("ethabi token error".to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err.to_string())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Contract error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
