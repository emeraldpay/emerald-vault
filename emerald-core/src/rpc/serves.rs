use super::Error;
use super::serialize::{RPCAccount, RPCTransaction};
use jsonrpc_core::{self, Params};
use std::path::PathBuf;
use std::str::FromStr;

use keystore::{KdfDepthLevel, KeyFile, list_accounts};
use core::Address;

/// Main chain id
pub const MAINNET_ID: u8 = 61;

/// Test chain id
pub const TESTNET_ID: u8 = 62;

pub fn current_version(params: ()) -> Result<&'static str, Error> {
    Ok(::version())
}

pub fn heartbeat(params: ()) -> Result<i64, Error> {
    use time::get_time;
    Ok(get_time().sec)
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum NewAccountParams {
    PassOnly((String,)),
    WithAccount((RPCAccount, String)),
}

pub fn new_account(params: NewAccountParams, sec: &KdfDepthLevel, keystore_path: &PathBuf) -> Result<String, Error> {
    let (account, pass) = match params {
        NewAccountParams::PassOnly((pass,)) => {
            (RPCAccount {
                name: "".to_string(),
                description: "".to_string(),
            },
             pass)
        }
        NewAccountParams::WithAccount((account, pass)) => (account, pass),
    };

    if pass.is_empty() {
        return Err(Error::InvalidDataFormat("Empty passphase".to_string()));
    }

    match KeyFile::new(&pass, &sec, Some(account.name), Some(account.description)) {
        Ok(kf) => {
            let addr = kf.address.to_string();
            match kf.flush(keystore_path) {
                Ok(_) => Ok(addr),
                Err(_) => Err(Error::RPC(jsonrpc_core::Error::internal_error())),
            }
        }
        Err(_) => Err(Error::InvalidDataFormat("Invalid Keyfile data format".to_string())),
    }
}

pub fn sign_transaction(params: (RPCTransaction, String), keystore_path: &PathBuf) -> Result<Params, Error> {
    let addr = Address::from_str(&params.0.from)?;

    match KeyFile::search_by_address(&addr, keystore_path) {
        Ok(kf) => {
            if let Ok(pk) = kf.decrypt_key(&params.1) {
                match params.0.try_into() {
                    Ok(tr) => Ok(tr.to_raw_params(pk, TESTNET_ID)),
                    Err(err) => Err(Error::InvalidDataFormat(err.to_string())),
                }
            } else {
                Err(Error::InvalidDataFormat("Invalid passphrase".to_string()))
            }
        }
        Err(_) => Err(Error::InvalidDataFormat("Can't find account".to_string())),
    }
}
