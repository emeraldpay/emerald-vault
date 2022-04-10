use crate::{
    convert::error::ConversionError,
    crypto::error::CryptoError,
};
use std::fmt::Display;
use emerald_hwkey::errors::HWKeyError;

#[derive(Debug, Display, Clone, PartialEq)]
pub enum VaultError {
    FilesystemError(String),
    UnsupportedDataError(String),
    InvalidDataError(String),
    IncorrectIdError,
    IncorrectBlockchainError,
    ConversionError(ConversionError),
    UnrecognizedError,
    PasswordRequired,
    DataNotFound,
    InvalidPrivateKey,
    PrivateKeyUnavailable,
    PublicKeyUnavailable,
    CryptoFailed(CryptoError),
    HWKeyFailed(HWKeyError),
    GlobalKeyRequired,
}

impl std::convert::From<ConversionError> for VaultError {
    fn from(err: ConversionError) -> Self {
        VaultError::ConversionError(err)
    }
}

impl std::convert::From<std::io::Error> for VaultError {
    fn from(err: std::io::Error) -> Self {
        VaultError::FilesystemError(err.to_string())
    }
}

impl std::convert::From<protobuf::ProtobufError> for VaultError {
    fn from(err: protobuf::ProtobufError) -> Self {
        VaultError::ConversionError(ConversionError::from(err))
    }
}

impl std::convert::From<uuid::Error> for VaultError {
    fn from(_: uuid::Error) -> Self {
        VaultError::IncorrectIdError
    }
}

impl std::convert::From<String> for VaultError {
    fn from(err: String) -> Self {
        VaultError::InvalidDataError(err)
    }
}

impl std::convert::From<()> for VaultError {
    fn from(_: ()) -> Self {
        VaultError::UnrecognizedError
    }
}

impl From<hex::FromHexError> for VaultError {
    fn from(err: hex::FromHexError) -> Self {
        VaultError::ConversionError(ConversionError::from(err))
    }
}

impl From<secp256k1::Error> for VaultError {
    fn from(err: secp256k1::Error) -> Self {
        VaultError::CryptoFailed(CryptoError::from(err))
    }
}

impl std::convert::From<std::convert::Infallible> for VaultError {
    fn from(_: std::convert::Infallible) -> Self {
        VaultError::UnrecognizedError
    }
}

impl std::convert::From<csv::Error> for VaultError {
    fn from(_: csv::Error) -> Self {
        VaultError::ConversionError(ConversionError::CSVError)
    }
}

impl std::convert::From<CryptoError> for VaultError {
    fn from(err: CryptoError) -> Self {
        VaultError::CryptoFailed(err)
    }
}

impl std::convert::From<HWKeyError> for VaultError {
    fn from(err: HWKeyError) -> Self {
        VaultError::HWKeyFailed(err)
    }
}

impl std::convert::From<hdpath::Error> for VaultError {
    fn from(err: hdpath::Error) -> Self {
        VaultError::UnsupportedDataError(format!("Invalid HDPath: {:?}", err))
    }
}

impl std::convert::From<rand::Error> for VaultError {
    fn from(err: rand::Error) -> Self {
        Self::from(CryptoError::from(err))
    }
}
