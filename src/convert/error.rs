use crate::error;
use crate::storage::error::VaultError;
use protobuf::ProtobufError;
use std::fmt::Display;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Display)]
pub enum ConversionError {
    InvalidArgument,
    InvalidJson,
    /// Value is the field name
    InvalidFieldValue(String),
    /// value is the field name
    FieldIsEmpty(String),
    /// value  is the field name
    UnsupportedValue(String),
    UnsuportedVersion,
    NotHex,
    CSVError,
    InvalidProtobuf,
    IOError,
    OtherError,
}

impl From<serde_json::Error> for ConversionError {
    fn from(_: serde_json::Error) -> Self {
        ConversionError::InvalidJson
    }
}

impl From<hex::FromHexError> for ConversionError {
    fn from(_: hex::FromHexError) -> Self {
        ConversionError::NotHex
    }
}

impl From<protobuf::ProtobufError> for ConversionError {
    fn from(err: protobuf::ProtobufError) -> Self {
        match err {
            protobuf::ProtobufError::IoError(_) => ConversionError::IOError,
            _ => ConversionError::InvalidProtobuf,
        }
    }
}

impl From<error::Error> for ConversionError {
    fn from(_: error::Error) -> Self {
        ConversionError::OtherError
    }
}
