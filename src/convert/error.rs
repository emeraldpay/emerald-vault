use crate::storage::error::VaultError;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ConversionError {
    InvalidArgument,
    InvalidJson,
    InvalidData(String),
    UnsuportedVersion
}

impl From<serde_json::Error> for ConversionError {
    fn from(_: serde_json::Error) -> Self {
        ConversionError::InvalidJson
    }
}

impl From<VaultError> for ConversionError {
    fn from(_: VaultError) -> Self {
        ConversionError::InvalidData("Vault Error".to_string())
    }
}

impl From<hex::FromHexError> for ConversionError {
    fn from(_: hex::FromHexError) -> Self {
        ConversionError::InvalidData("Not HEX".to_string())
    }
}
