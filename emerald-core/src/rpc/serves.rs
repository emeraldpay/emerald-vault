use super::Error;
use super::serialize::RPCTransaction;
use core::Address;
use jsonrpc_core::{self, Params, Value};

use addressbook::Addressbook;
use keystore::{KdfDepthLevel, KeyFile};
use std::path::PathBuf;
use std::str::FromStr;

fn to_chain_id(chain: String, chain_id: Option<usize>) -> u8 {
    if chain_id.is_some() {
        chain_id.unwrap() as u8
    } else if chain == "mainnet" {
        61
    } else if chain == "testnet" {
        62
    } else {
        61
    }
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Either<T, U> {
    Left(T),
    Right(U)
}

impl<T, U: Default> Either<T, U> {
    pub fn into_right(self) -> U {
        match self {
            Either::Left(t) => U::default(),
            Either::Right(u) => u,
        }
    }
}

impl<T: Default, U> Either<T, U> {
    pub fn into_left(self) -> T {
        match self {
            Either::Left(t) => t,
            Either::Right(u) => T::default(),
        }
    }
}

impl<T, U: Default> Either<(T,), (T, U)> {
    fn into_full(self) -> (T, U) {
        match self {
            Either::Left((t,)) => (t, U::default()),
            Either::Right((t, u)) => (t, u),
        }
    }
}

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
pub struct ListAccountsAdditional {
    #[serde(default)]
    chain: String,
    #[serde(default)]
    chain_id: Option<usize>,
    #[serde(default)]
    show_hidden: bool,
}

pub fn list_accounts(params: Either<(), (ListAccountsAdditional,)>,
                     keystore_path: &PathBuf)
                     -> Result<Vec<Value>, Error> {
    let address_book = Addressbook::new(keystore_path.clone());
    Ok(address_book.list())
}

#[derive(Deserialize)]
pub struct NewAccountAccount {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    passphrase: String,
}

#[derive(Deserialize, Default)]
pub struct NewAccountAdditional {
    #[serde(default)]
    chain: String,
    #[serde(default)]
    chain_id: Option<usize>,
}

pub fn new_account(params: Either<(NewAccountAccount,), (NewAccountAccount, NewAccountAdditional)>,
                   sec: &KdfDepthLevel,
                   keystore_path: &PathBuf)
                   -> Result<String, Error> {
    let (account, additional) = params.into_full();

    if account.passphrase.is_empty() {
        return Err(Error::InvalidDataFormat("Empty passphase".to_string()));
    }

    match KeyFile::new(&account.passphrase, &sec, Some(account.name), Some(account.description)) {
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

pub fn sign_transaction(params: (RPCTransaction, String),
                        keystore_path: &PathBuf)
                        -> Result<Params, Error> {
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
