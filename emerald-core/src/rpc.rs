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
//! # JSON RPC module

mod common;
mod error;
mod serialize;
mod serves;

pub use self::error::Error;
use super::core;
use super::keystore::KdfDepthLevel;
use super::storage::{self, StorageController};
use super::util::{align_bytes, to_arr, to_even_str, to_u64, trim_hex, ToHex};
use crate::hdwallet::WManager;
use jsonrpc_core::{Error as JsonRpcError, IoHandler, Params};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use log::Level;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{self, Value};
use std::cell::RefCell;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

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
    p.parse()
        .map_err(|_| JsonRpcError::invalid_params("Corrupted input parameters".to_string()))
}

/// Start an HTTP RPC endpoint
pub fn start(addr: &SocketAddr, storage_ctrl: StorageController, sec_level: Option<KdfDepthLevel>) {
    let sec_level = sec_level.unwrap_or_default();
    let storage_ctrl = Arc::new(Mutex::new(storage_ctrl));

    let wallet_manager = match WManager::new(None) {
        Ok(wm) => Arc::new(Mutex::new(RefCell::new(wm))),
        Err(e) => panic!("Can't create HID endpoint: {}", e.to_string()),
    };

    let mut io = IoHandler::default();

    {
        io.add_method("emerald_currentVersion", move |p: Params| {
            parse(p)?;
            wrapper(serves::current_version())
        });
    }

    {
        io.add_method("emerald_heartbeat", move |p: Params| {
            parse(p)?;
            wrapper(serves::heartbeat())
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_listAddresses", move |p: Params| {
            wrapper(serves::list_addresses(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_importAddress", move |p: Params| {
            wrapper(serves::import_address(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_deleteAddress", move |p: Params| {
            wrapper(serves::delete_address(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);

        io.add_method("emerald_listAccounts", move |p: Params| {
            wrapper(serves::list_accounts(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_hideAccount", move |p: Params| {
            wrapper(serves::hide_account(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);

        io.add_method("emerald_unhideAccount", move |p: Params| {
            wrapper(serves::unhide_account(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_shakeAccount", move |p: Params| {
            wrapper(serves::shake_account(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_updateAccount", move |p: Params| {
            wrapper(serves::update_account(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_importAccount", move |p: Params| {
            wrapper(serves::import_account(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_exportAccount", move |p: Params| {
            wrapper(serves::export_account(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_newAccount", move |p: Params| {
            wrapper(serves::new_account(parse(p)?, &sec_level, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        let wm = Arc::clone(&wallet_manager);
        io.add_method("emerald_signTransaction", move |p: Params| {
            wrapper(serves::sign_transaction(parse(p)?, &storage_ctrl, &wm))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        let wm = Arc::clone(&wallet_manager);
        io.add_method("emerald_sign", move |p: Params| {
            wrapper(serves::sign(parse(p)?, &storage_ctrl, &wm))
        });
    }

    {
        io.add_method("emerald_encodeFunctionCall", move |p: Params| {
            wrapper(serves::encode_function_call(parse(p)?))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_listContracts", move |p: Params| {
            wrapper(serves::list_contracts(parse(p)?, &storage_ctrl))
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_importContract", move |p: Params| {
            wrapper(serves::import_contract(parse(p)?, &storage_ctrl))
        });
    }

    //    {
    //        let storage_ctrl = Arc::clone(&storage_ctrl);
    //        io.add_method("emerald_exportContract", move |p: Params| {
    //            wrapper(serves::export_contract(parse(p)?, &storage_ctrl))
    //        });
    //    }

    {
        io.add_method("emerald_generateMnemonic", move |_: Params| {
            wrapper(serves::generate_mnemonic())
        });
    }

    {
        let storage_ctrl = Arc::clone(&storage_ctrl);
        io.add_method("emerald_importMnemonic", move |p: Params| {
            wrapper(serves::import_mnemonic(
                parse(p)?,
                &sec_level,
                &storage_ctrl,
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

    if log_enabled!(Level::Info) {
        info!("Connector started on http://{}", server.address());
    }

    server.wait();
}
