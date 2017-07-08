//! # Contract

use ethabi;
use ethabi::{Function, Interface};
use ethabi::token::Token;
use std::fmt;

/// Contract specification
#[derive(Clone, Debug, Deserialize)]
pub struct Contract {
    abi: Interface,
}

impl Contract {
    /// Try to convert deserialized vector to Contract ABI.
    ///
    /// # Arguments
    ///
    /// * `DATA` - A byte slice
    ///
    /// # Example
    ///
    /// ```
    /// const DATA: &[u8] = b"[{\"constant\":true,\"inputs\":[],\"name\":\"name\",\
    ///             \"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\
    ///             \"payable\":false,\"type\":\"function\"}]";
    /// let contract = emerald_core::Contract::from(DATA).unwrap();
    /// assert_eq!(contract.to_string(),
    ///            "Interface([Function(Function { name: \"name\", inputs: [],\
    ///             outputs: [Param { name: \"\", kind: String }] })])");
    /// ```
    pub fn from(data: &[u8]) -> Result<Self, ethabi::spec::Error> {
        let abi = Interface::load(data)?;
        Ok(Contract { abi: abi })
    }

    /// Returns specification of contract function given the function name.
    pub fn function(&self, name: String) -> Option<Function> {
        match self.abi.function(name) {
            Some(f) => Some(Function::new(f)),
            _ => None,
        }
    }

    /// Encode ABI function call with input params
    pub fn function_encode(
        &self,
        name: String,
        params: Vec<Token>,
    ) -> Result<Vec<u8>, ethabi::Error> {
        match self.function(name) {
            Some(f) => f.encode_call(params),
            None => Err(ethabi::Error::InvalidName),
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
    use ethabi::spec::{Function as FunctionInterface, Param, ParamType};

    #[test]
    fn should_display_contract_abi() {
        let c = b"[{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"name\":\"\",\
                 \"type\":\"string\"}],\"payable\":false,\"type\":\"function\"}]";
        let contract = Contract::from(c).unwrap();
        format!("{}", contract);
    }

    #[test]
    fn should_return_correct_function() {
        let c = b"[{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\
                 \"balanceOf\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":\
                 false,\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"name\",\
                 \"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"type\":\
                 \"function\"}]";
        let interface = FunctionInterface {
            name: "balanceOf".to_owned(),
            inputs: vec![
                Param {
                    name: "".to_owned(),
                    kind: ParamType::Address,
                },
            ],
            outputs: vec![
                Param {
                    name: "a".to_owned(),
                    kind: ParamType::Uint(256),
                },
            ],
        };
        let contract = Contract::from(c).unwrap();
        let f = contract.function("balanceOf".to_string()).unwrap();
        assert_eq!(f.input_params(), Function::new(interface).input_params());
    }
}
