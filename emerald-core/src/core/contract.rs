//! # Contract

use super::Error;
use hex::{FromHex, ToHex};
use std::{fmt, ops};
use std::str::FromStr;
use ethabi::{Function, Interface};
use serde_json;

/// Contract specification
#[derive(Clone, Debug, Deserialize)]
pub struct Contract {
    abi: Interface,
}

impl Contract {
    /// Try to convert deserialized vector to Contract ABI.
    ///
    /// # Example
    ///
    /// ```
    /// let contract = emerald_core::Contract::try_from(&"[]").unwrap();
    /// assert_eq!(contract.to_string(), "[{},{}]");
    /// ```
    pub fn try_from(data: &str) -> Result<Self, Error> {
        let abi: Interface = try!(serde_json::from_str(data)
            .map_err(|e| Error::InvalidHexLength(e.to_string())));
        Ok(Contract{ abi: abi })
    }

    /// Returns specification of contract function.
    pub fn function(&self, name: String) -> Option<Function> {
        match self.abi.function(name) {
            Some(f) => Some(Function::new(f)),
            _ => None
        }
    }
}


impl fmt::Display for Contract {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.abi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_display_contract_abi() {
        let c = "[{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"type\":\"function\"}]";
        let contract = Contract(c);
        assert_eq!(
            contract.to_string(),
            c
        );
    }
}