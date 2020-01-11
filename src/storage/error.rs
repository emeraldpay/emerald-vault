use crate::core;
use std::fmt::Display;
use crate::convert::error::ConversionError;
use crate::crypto::error::CryptoError;
use crate::hdwallet::Error as HWalletError;

#[derive(Debug, Display, Clone)]
pub enum VaultError {
    FilesystemError(String),
    ProtobufError(String),
    UnsupportedDataError(String),
    InvalidDataError(String),
    IncorrectIdError,
    ConversionError,
    UnrecognizedError,
    PasswordRequired,
    DataNotFound,
    InvalidPrivateKey,
    PrivateKeyUnavailable
}

impl std::convert::From<ConversionError> for VaultError {
    fn from(_: ConversionError) -> Self {
       VaultError::ConversionError
    }
}

impl std::convert::From<std::io::Error> for VaultError {
    fn from(err: std::io::Error) -> Self {
        VaultError::FilesystemError(err.to_string())
    }
}

impl std::convert::From<protobuf::ProtobufError> for VaultError {
    fn from(err: protobuf::ProtobufError) -> Self {
        VaultError::ProtobufError(err.to_string())
    }
}

impl std::convert::From<uuid::ParseError> for VaultError {
    fn from(_: uuid::ParseError) -> Self {
        VaultError::IncorrectIdError
    }
}

impl std::convert::From<String> for VaultError {
    fn from(err: String) -> Self {
        VaultError::InvalidDataError(err)
    }
}

impl std::convert::From<core::error::Error> for VaultError {
    fn from(err: core::error::Error) -> Self {
        match err {
            core::error::Error::InvalidHexLength(_) => VaultError::InvalidDataError("Invalid input length".to_string()),
            _ => VaultError::InvalidDataError("Invalid data".to_string())
        }
    }
}

impl std::convert::From<()> for VaultError {
    fn from(_: ()) -> Self {
        VaultError::UnrecognizedError
    }
}

impl std::convert::From<std::convert::Infallible> for VaultError {
    fn from(_: std::convert::Infallible) -> Self {
        VaultError::UnrecognizedError
    }
}

impl std::convert::From<csv::Error> for VaultError {
    fn from(_: csv::Error) -> Self {
        VaultError::InvalidDataError("Not a CSV".to_string())
    }
}

impl std::convert::From<hex::FromHexError> for VaultError {
    fn from(_: hex::FromHexError) -> Self {
        VaultError::InvalidDataError("Not HEX".to_string())
    }
}

impl std::convert::From<CryptoError> for VaultError {
    fn from(_: CryptoError) -> Self {
        //TODO
        VaultError::ConversionError
    }
}

impl std::convert::From<HWalletError> for VaultError {
    fn from(_: HWalletError) -> Self {
        //TODO
        VaultError::ConversionError
    }
}
