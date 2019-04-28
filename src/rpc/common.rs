/*
Copyright 2019 ETCDEV GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//! Common types for JSON RPC handlers
//!

use super::Error;
use util;

/// Trait to access a common chain name and id params
///
pub trait CommonChainParams {
    fn get_chain(&self) -> String;
    fn get_chain_id(&self) -> Option<usize>;
}

/// Check correspondence between chain name and chain numerical ID
/// If succeed, returns tuple of chain name and chain id.
///
///
/// # Arguments
///
/// * p - trait object to access chain name and id
///
/// # Errors
///
/// Return `Error` if parameters does not match
///
pub fn extract_chain_params(p: &CommonChainParams) -> Result<(String, u8), Error> {
    let name_param = p.get_chain();
    let id_param = p.get_chain_id();
    let mut id: u8;
    let mut name: String;

    if !name_param.is_empty() && id_param.is_some() {
        id = check_chain_name(&name_param)?;
        name = check_chain_id(id_param.unwrap() as u8)?;
        if (id_param.unwrap() as u8) != id {
            return Err(Error::InvalidDataFormat(format!(
                "Inconsistent chain name: {} and chain id: {}",
                name_param, id
            )));
        }
    } else if !name_param.is_empty() {
        name = name_param.clone();
        id = check_chain_name(&name_param)?;
    } else if id_param.is_some() {
        id = id_param.unwrap() as u8;
        name = check_chain_id(id)?;
    } else {
        return Err(Error::InvalidDataFormat(
            "Required chain name or chain id parameter".to_string(),
        ));
    }

    Ok((name, id))
}

fn check_chain_name(n: &str) -> Result<u8, Error> {
    match util::to_chain_id(n) {
        Some(id) => Ok(id),
        None => {
            return Err(Error::InvalidDataFormat(format!(
                "Invalid chain name: {}",
                n
            )));
        }
    }
}

fn check_chain_id(id: u8) -> Result<String, Error> {
    match util::to_chain_name(id) {
        Some(n) => Ok(n.to_string()),
        None => {
            return Err(Error::InvalidDataFormat(format!(
                "Invalid chain id: {}",
                id
            )));
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Either<T, U> {
    Left(T),
    Right(U),
}

impl<T, U: Default> Either<T, U> {
    pub fn into_right(self) -> U {
        match self {
            Either::Left(_) => U::default(),
            Either::Right(u) => u,
        }
    }
}

impl<T, U: Default> Either<(T,), (T, U)> {
    pub fn into_full(self) -> (T, U) {
        match self {
            Either::Left((t,)) => (t, U::default()),
            Either::Right((t, u)) => (t, u),
        }
    }
}

#[derive(Deserialize)]
pub struct ShakeAccountAccount {
    pub address: String,
    pub old_passphrase: String,
    pub new_passphrase: String,
}

#[derive(Deserialize)]
pub struct UpdateAccountAccount {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub name: String,
    pub description: String,
}

#[derive(Deserialize, Debug)]
pub struct NewAccountAccount {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub passphrase: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ListAccountAccount {
    pub name: String,
    pub address: String,
    pub description: String,
    pub hardware: bool,
    pub is_hidden: bool,
}

#[derive(Deserialize, Default, Debug)]
pub struct ListAccountsAdditional {
    #[serde(default)]
    pub chain: String,
    #[serde(default)]
    pub chain_id: Option<usize>,
    #[serde(default)]
    pub show_hidden: bool,
    #[serde(default)]
    pub hd_path: Option<String>,
}

impl CommonChainParams for ListAccountsAdditional {
    fn get_chain(&self) -> String {
        self.chain.clone()
    }

    fn get_chain_id(&self) -> Option<usize> {
        self.chain_id
    }
}

#[derive(Deserialize)]
pub struct SelectedAccount {
    pub address: String,
}

#[derive(Deserialize, Default, Debug)]
pub struct CommonAdditional {
    #[serde(default)]
    pub chain: String,
    #[serde(default)]
    pub chain_id: Option<usize>,
}

impl CommonChainParams for CommonAdditional {
    fn get_chain(&self) -> String {
        self.chain.clone()
    }

    fn get_chain_id(&self) -> Option<usize> {
        self.chain_id
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct SignTxTransaction {
    pub from: String,
    pub to: String,
    pub gas: String,
    #[serde(rename = "gasPrice")]
    pub gas_price: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub data: String,
    pub nonce: String,
    #[serde(default)]
    pub passphrase: Option<String>,
}

#[derive(Deserialize, Default, Debug)]
pub struct SignTxAdditional {
    #[serde(default)]
    pub chain: String,
    #[serde(default)]
    pub chain_id: Option<usize>,
    #[serde(default)]
    pub hd_path: Option<String>,
}

impl CommonChainParams for SignTxAdditional {
    fn get_chain(&self) -> String {
        self.chain.clone()
    }

    fn get_chain_id(&self) -> Option<usize> {
        self.chain_id
    }
}

#[derive(Deserialize, Debug)]
pub struct SignData {
    pub address: String,
    pub data: String,
    #[serde(default)]
    pub passphrase: Option<String>,
}

#[derive(Deserialize, Default, Debug)]
pub struct FunctionParams {
    pub values: Vec<String>,
    pub types: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct NewMnemonicAccount {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub password: String,
    pub mnemonic: String,
    pub hd_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_extract_chain_params() {
        let params = CommonAdditional {
            chain: "etc".to_string(),
            chain_id: Some(61),
        };

        let (name, id) = extract_chain_params(&params).unwrap();
        assert_eq!(name, "etc");
        assert_eq!(id, 61);
    }

    #[test]
    fn should_check_empty_chain_name() {
        let params = CommonAdditional {
            chain: "".to_string(),
            chain_id: Some(61),
        };

        let (name, id) = extract_chain_params(&params).unwrap();
        assert_eq!(name, "etc");
        assert_eq!(id, 61);
    }

    #[test]
    fn should_check_empty_chain_id() {
        let params = CommonAdditional {
            chain: "etc".to_string(),
            chain_id: None,
        };

        let (name, id) = extract_chain_params(&params).unwrap();
        assert_eq!(name, "etc");
        assert_eq!(id, 61);
    }

    #[test]
    fn should_check_empty_chain_params() {
        let params = CommonAdditional {
            chain: "".to_string(),
            chain_id: None,
        };

        let res = extract_chain_params(&params);
        assert!(res.is_err());
    }
}
