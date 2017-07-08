//! # Contract

use super::Error;
use ethabi::{Encoder, Function, Interface};
use ethabi::spec::param_type::{ParamType, Reader};
use ethabi::token::{LenientTokenizer, Token, Tokenizer};
use hex::ToHex;
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
    pub fn from(data: &[u8]) -> Result<Self, Error> {
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
    pub fn serialize_function_call(
        &self,
        name: String,
        params: Vec<Token>,
    ) -> Result<Vec<u8>, Error> {
        let f = self.function(name).unwrap();
        f.encode_call(params).map_err(From::from)
    }

    /// Encode ABI input params to hex string
    pub fn serialize_params(types: Vec<String>, values: Vec<String>) -> Result<String, Error> {
        let types: Result<Vec<ParamType>, _> = types.iter().map(|s| Reader::read(s)).collect();

        let types = try!(types);

        let params: Vec<_> = types.into_iter().zip(values.into_iter()).collect();

        let tokens = params
            .iter()
            .map(|&(ref param, ref value)| {
                LenientTokenizer::tokenize(param, value)
            })
            .collect::<Result<_, _>>()?;

        let result = Encoder::encode(tokens);

        Ok(result.to_hex())
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
