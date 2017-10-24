use ethabi;
use std::{error, fmt, io};
use std::string::ToString;

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
    fn from(err: ethabi::Error) -> Self {
        Error::InvalidContract("".to_string())
    }
}

impl From<ethabi::spec::Error> for Error {
    fn from(err: ethabi::spec::Error) -> Self {
        Error::InvalidContract("".to_string())
    }
}

impl From<ethabi::spec::param_type::Error> for Error {
    fn from(err: ethabi::spec::param_type::Error) -> Self {
        Error::InvalidContract("".to_string())
    }
}

impl From<ethabi::token::Error> for Error {
    fn from(err: ethabi::token::Error) -> Self {
        Error::InvalidContract("".to_string())
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
