//! # JSON RPC module

mod serialize;
mod error;
mod serves;

pub use self::error::Error;
use super::core;
use super::keystore::KdfDepthLevel;
use super::storage::{self, ChainStorage, Storages, default_keystore_path};
use super::util::{ToHex, align_bytes, to_arr, to_chain_id, to_even_str, to_u64, trim_hex};
use hdwallet::WManager;
use jsonrpc_core::{Error as JsonRpcError, IoHandler, Params};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use log::LogLevel;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{self, Value};
use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(feature = "default")]
use storage::dbStorage;
#[cfg(feature = "fs-storage")]
use storage::fsStorage;

fn wrapper<T: Serialize>(value: Result<T, Error>) -> Result<Value, JsonRpcError> {
    if value.is_err() {
        return Err(JsonRpcError::invalid_params(
            value.err().unwrap().to_string(),
        ));
    }
    let value = value.unwrap();
    let result = serde_json::to_value(value);
    match result {
        Ok(value) => Ok(value),
        Err(e) => Err(JsonRpcError::invalid_params(e.to_string())),
    }
}

fn parse<T>(p: Params) -> Result<T, JsonRpcError>
where
    T: DeserializeOwned,
{
    p.parse().map_err(|_| {
        JsonRpcError::invalid_params("Corrupted input parameters".to_string())
    })
}


/// Start an HTTP RPC endpoint
pub fn start(
    addr: &SocketAddr,
    chain_name: &str,
    base_path: Option<PathBuf>,
    sec_level: Option<KdfDepthLevel>,
) {
    let sec_level = sec_level.unwrap_or_default();

    let storage = match base_path {
        Some(p) => Storages::new(p),
        None => Storages::default(),
    };

    if storage.init().is_err() {
        panic!("Unable to initialize storage");
    }

    let chain = ChainStorage::new(&storage, chain_name.to_string());
    if chain.init().is_err() {
        panic!("Unable to initialize chain");
    }

    let keystore_path = default_keystore_path(&chain.id);
    #[cfg(feature = "default")]
    let storage = match dbStorage::new(keystore_path) {
        Ok(db) => Arc::new(db),
        Err(_) => panic!("Can't create database keyfile storage"),
    };
    #[cfg(feature = "fs-storage")]
    let storage = match fsStorage::new(keystore_path) {
        Ok(fs) => Arc::new(fs),
        Err(_) => panic!("Can't create filesystem keyfile storage"),
    };

    let wallet_manager = match WManager::new(None) {
        Ok(wm) => Mutex::new(RefCell::new(wm)),
        Err(_) => panic!("Can't create HID endpoint"),
    };

    let mut io = IoHandler::default();

    {
        io.add_method("emerald_currentVersion", move |p: Params| {
            wrapper(serves::current_version(parse(p)?))
        });
    }

    {
        io.add_method("emerald_heartbeat", move |p: Params| {
            wrapper(serves::heartbeat(parse(p)?))
        });
    }

    {
        let storage = storage.clone();

        io.add_method("emerald_listAccounts", move |p: Params| {
            wrapper(serves::list_accounts(parse(p)?, &storage))
        });
    }

    {
        let storage = storage.clone();

        io.add_method("emerald_hideAccount", move |p: Params| {
            wrapper(serves::hide_account(parse(p)?, &storage))
        });
    }

    {
        let storage = storage.clone();

        io.add_method("emerald_unhideAccount", move |p: Params| {
            wrapper(serves::unhide_account(parse(p)?, &storage))
        });
    }

    {
        let storage = storage.clone();

        io.add_method("emerald_shakeAccount", move |p: Params| {
            wrapper(serves::shake_account(parse(p)?, &storage))
        });
    }

    {
        let storage = storage.clone();

        io.add_method("emerald_updateAccount", move |p: Params| {
            wrapper(serves::update_account(parse(p)?, &storage))
        });
    }

    {
        let storage = storage.clone();

        io.add_method("emerald_importAccount", move |p: Params| {
            wrapper(serves::import_account(parse(p)?, &storage))
        });
    }

    {
        let storage = storage.clone();

        io.add_method("emerald_exportAccount", move |p: Params| {
            wrapper(serves::export_account(parse(p)?, &storage))
        });
    }

    {
        let sec = sec_level;
        let storage = storage.clone();

        io.add_method("emerald_newAccount", move |p: Params| {
            wrapper(serves::new_account(parse(p)?, &sec, &storage))
        });
    }

    {
        let storage = storage.clone();
        let chain_id = to_chain_id(chain_name).unwrap();
        io.add_method("emerald_signTransaction", move |p: Params| {
            wrapper(serves::sign_transaction(
                parse(p)?,
                &storage,
                chain_id,
                &wallet_manager,
            ))
        });
    }

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![
            AccessControlAllowOrigin::Any,
            AccessControlAllowOrigin::Null,
        ]))
        .start_http(addr)
        .expect("Expect to build HTTP RPC server");

    if log_enabled!(LogLevel::Info) {
        info!("Connector started on http://{}", server.address());
    }

    server.wait();
}
