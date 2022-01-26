use std::fmt::Display;

#[derive(Debug, Clone, Eq, PartialEq, Display)]
pub enum CryptoError {
    InvalidParams(String),
    InvalidKey,
    WrongKey,
    UnsupportedSource(String),
    NoEntropy,
    GlobalKeyRequired,
    PasswordRequired,
}

impl From<scrypt::errors::InvalidParams> for CryptoError {
    fn from(e: scrypt::errors::InvalidParams) -> Self {
        CryptoError::InvalidParams(e.to_string())
    }
}

impl From<scrypt::errors::InvalidOutputLen> for CryptoError {
    fn from(e: scrypt::errors::InvalidOutputLen) -> Self {
        CryptoError::InvalidParams(e.to_string())
    }
}

impl From<argon2::Error> for CryptoError {
    fn from(e: argon2::Error) -> Self {
        CryptoError::InvalidParams(e.to_string())
    }
}

impl From<rand::Error> for CryptoError {
    fn from(_: rand::Error) -> Self {
        CryptoError::NoEntropy
    }
}

