
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CryptoError {
    InvalidParams,
    InvalidKey,
    WrongKey,
    UnsupportedSource(String),
    NoEntropy
}

impl From<scrypt::errors::InvalidParams> for CryptoError {
    fn from(x: scrypt::errors::InvalidParams) -> Self {
        CryptoError::InvalidParams
    }
}

impl From<scrypt::errors::InvalidOutputLen> for CryptoError {
    fn from(x: scrypt::errors::InvalidOutputLen) -> Self {
        CryptoError::InvalidParams
    }
}
