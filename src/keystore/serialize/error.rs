//! # Serialize keystore files (UTC / JSON) errors

use std::{error, fmt};

/// Keystore file serialize errors
#[derive(Debug)]
pub enum SerializeError {
    /// An unsupported version
    UnsupportedVersion(u8),
}

impl fmt::Display for SerializeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SerializeError::UnsupportedVersion(ver) => {
                write!(f, "Unsupported keystore file version: {}", ver)
            }
        }
    }
}

impl error::Error for SerializeError {
    fn description(&self) -> &str {
        "Keystore file serialize error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}
