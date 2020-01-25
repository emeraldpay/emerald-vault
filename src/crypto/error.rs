use std::fmt::Display;

#[derive(Debug, Clone, Eq, PartialEq, Display)]
pub enum CryptoError {
    InvalidParams,
    InvalidKey,
    WrongKey,
    UnsupportedSource(String),
    NoEntropy,
}

impl From<scrypt::errors::InvalidParams> for CryptoError {
    fn from(_: scrypt::errors::InvalidParams) -> Self {
        CryptoError::InvalidParams
    }
}

impl From<scrypt::errors::InvalidOutputLen> for CryptoError {
    fn from(_: scrypt::errors::InvalidOutputLen) -> Self {
        CryptoError::InvalidParams
    }
}
