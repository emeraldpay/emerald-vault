//! # JSON RPC module

mod serialize;
mod error;
mod serves;

pub use self::error::Error;
use super::core;
use super::keystore::KdfDepthLevel;
use super::storage::{ChainStorage, Storages, default_keystore_path};
use super::util::{ToHex, align_bytes, to_arr, to_even_str, to_u64, trim_hex};
use jsonrpc_core::{Error as JsonRpcError, IoHandler, Params};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use log::LogLevel;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{self, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

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
pub fn start(addr: &SocketAddr, base_path: Option<PathBuf>, sec_level: Option<KdfDepthLevel>) {
    let sec_level = sec_level.unwrap_or_default();

    let storage = match base_path {
        Some(p) => Storages::new(p),
        None => Storages::default(),
    };

    if storage.init().is_err() {
        panic!("Unable to initialize storage");
    }

    let chain = ChainStorage::new(&storage, "default".to_string());
    if chain.init().is_err() {
        panic!("Unable to initialize chain");
    }
    let keystore_path = Arc::new(default_keystore_path(&chain.id));

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
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_listAccounts", move |p: Params| {
            wrapper(serves::list_accounts(parse(p)?, &keystore_path))
        });
    }

    {
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_hideAccount", move |p: Params| {
            wrapper(serves::hide_account(parse(p)?, &keystore_path))
        });
    }

    {
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_unhideAccount", move |p: Params| {
            wrapper(serves::unhide_account(parse(p)?, &keystore_path))
        });
    }

    {
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_shakeAccount", move |p: Params| {
            wrapper(serves::shake_account(parse(p)?, &keystore_path))
        });
    }

    {
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_updateAccount", move |p: Params| {
            wrapper(serves::update_account(parse(p)?, &keystore_path))
        });
    }

    {
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_importAccount", move |p: Params| {
            wrapper(serves::import_account(parse(p)?, &keystore_path))
        });
    }

    {
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_exportAccount", move |p: Params| {
            wrapper(serves::export_account(parse(p)?, &keystore_path))
        });
    }

    {
        let sec = sec_level;
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_newAccount", move |p: Params| {
            wrapper(serves::new_account(parse(p)?, &sec, &keystore_path))
        });
    }

    {
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_signTransaction", move |p: Params| {
            wrapper(serves::sign_transaction(parse(p)?, &keystore_path))
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
