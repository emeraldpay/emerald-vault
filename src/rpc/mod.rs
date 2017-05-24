//! # JSON RPC module

mod http;
mod serialize;
mod error;

pub use self::error::Error;
use super::contract::Contracts;
use super::core::{self, Transaction};
use super::keystore::{KdfDepthLevel, KeyFile, list_accounts};
use super::storage::{ChainStorage, Storages, default_keystore_path};
use super::util::{ToHex, align_bytes, to_arr, to_u64, trim_hex};
use futures;
use jsonrpc_core::{Error as JsonRpcError, ErrorCode, IoHandler, Params};
use jsonrpc_core::futures::Future;
use jsonrpc_minihttp_server::{DomainsValidation, ServerBuilder, cors};
use log::LogLevel;
use rustc_serialize::json;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// RPC methods
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ClientMethod {
    /// [web3_clientVersion](https://github.com/ethereum/wiki/wiki/JSON-RPC#web3_clientversion)
    Version,

    /// [eth_syncing](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_syncing)
    EthSyncing,

    /// [eth_blockNumber](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_blocknumber)
    EthBlockNumber,

    /// [eth_accounts](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_accounts)
    EthAccounts,

    /// [eth_getBalance](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getbalance)
    EthGetBalance,

    /// [eth_getTransactionCount](
    /// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gettransactioncount)
    EthGetTxCount,

    /// [eth_getTransactionByHash](
    /// https://github.com/ethereumproject/wiki/wiki/JSON-RPC#eth_gettransactionbyhash)
    EthGetTxByHash,

    /// [eth_sendRawTransaction](
    /// https://github.com/paritytech/parity/wiki/JSONRPC-eth-module#eth_sendrawtransaction)
    EthSendRawTransaction,

    /// [eth_call](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_call)
    EthCall,

    /// [trace_call](https://github.com/ethereumproject/emerald-rs/issues/30#issuecomment-291987132)
    EthTraceCall,
}

/// PRC method's parameters
#[derive(Clone, Debug, PartialEq)]
pub struct MethodParams<'a>(pub ClientMethod, pub &'a Params);

/// Start an HTTP RPC endpoint
pub fn start(addr: &SocketAddr,
             client_addr: &SocketAddr,
             base_path: Option<PathBuf>,
             sec_level: KdfDepthLevel) {
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
    let url = Arc::new(http::AsyncWrapper::new(&format!("http://{}", client_addr)));

    {
        let url = url.clone();

        io.add_async_method("web3_clientVersion",
                            move |p| url.request(&MethodParams(ClientMethod::Version, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_syncing",
                            move |p| url.request(&MethodParams(ClientMethod::EthSyncing, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_blockNumber",
                            move |p| url.request(&MethodParams(ClientMethod::EthBlockNumber, &p)));
    }


    {
        let keystore_path = keystore_path.clone();
        let accounts_callback = move |_| match list_accounts(keystore_path.as_ref()) {
            Ok(list) => {
                let accounts = list.iter().map(|s| Value::String(s.clone())).collect();
                futures::done(Ok(Value::Array(accounts))).boxed()
            }
            Err(err) => futures::failed(JsonRpcError::invalid_params(err.to_string())).boxed(),
        };

        io.add_async_method("eth_accounts", accounts_callback);
    }

    {
        let url = url.clone();

        io.add_async_method("eth_getBalance",
                            move |p| url.request(&MethodParams(ClientMethod::EthGetBalance, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_getTransactionCount",
                            move |p| url.request(&MethodParams(ClientMethod::EthGetTxCount, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_getTransactionByHash",
                            move |p| url.request(&MethodParams(ClientMethod::EthGetTxByHash, &p)));
    }

    {
        let url = url.clone();

        let callback = move |p| {
            let pk = KeyFile::default().decrypt_key("");
            match Transaction::try_from(&p) {
                Ok(tr) => {
                    url.request(&MethodParams(ClientMethod::EthSendRawTransaction,
                                              &tr.to_raw_params(pk.unwrap())))
                }
                Err(err) => {
                    futures::done(Err(JsonRpcError::invalid_params(err.to_string()))).boxed()
                }
            }
        };

        io.add_async_method("eth_sendTransaction", callback);
    }

    {
        let url = url.clone();

        io.add_async_method("eth_sendRawTransaction", move |p| {
            url.request(&MethodParams(ClientMethod::EthSendRawTransaction, &p))
        });
    }

    {
        let url = url.clone();

        io.add_async_method("eth_call",
                            move |p| url.request(&MethodParams(ClientMethod::EthCall, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_traceCall",
                            move |p| url.request(&MethodParams(ClientMethod::EthTraceCall, &p)));
    }

    {
        let sec = sec_level.clone();
        let keystore_path = keystore_path.clone();
        let create_callback = move |p| match Params::parse::<Value>(p) {
            Ok(ref v) => {
                let data = v.get(0);
                if data.is_none() {
                    return futures::failed(JsonRpcError::invalid_params("Invalid JSON object"))
                               .boxed();
                }
                let p = data.unwrap();

                if p.as_str().is_none() {
                    return futures::failed(JsonRpcError::invalid_params("Invalid password format"))
                               .boxed();
                }
                let passwd = p.as_str().unwrap();

                match KeyFile::new(passwd, &sec) {
                    Ok(kf) => {
                        let addr = kf.address.to_string();
                        match kf.flush(keystore_path.as_ref()) {
                            Ok(_) => futures::done(Ok(Value::String(addr))).boxed(),
                            Err(_) => futures::done(Err(JsonRpcError::internal_error())).boxed(),
                        }
                    }
                    Err(_) => {
                        futures::done(Err(JsonRpcError::invalid_params("Invalid Keyfile data \
                                                                        format")))
                                .boxed()
                    }
                }
            }
            Err(_) => {
                futures::failed(JsonRpcError::invalid_params("Invalid password format")).boxed()
            }
        };

        io.add_async_method("personal_newAccount", create_callback);
    }

    {
        let keystore_path = keystore_path.clone();
        let import_callback = move |p| match Params::parse::<Value>(p) {
            Ok(ref v) => {
                match json::decode::<KeyFile>(&v.to_string()) {
                    Ok(kf) => {
                        let addr = kf.address.to_string();
                        match kf.flush(keystore_path.as_ref()) {
                            Ok(_) => futures::done(Ok(Value::String(addr))).boxed(),
                            Err(_) => futures::done(Err(JsonRpcError::internal_error())).boxed(),
                        }
                    }
                    Err(_) => {
                        futures::done(Err(JsonRpcError::invalid_params("Invalid Keyfile data \
                                                                    format")))
                                .boxed()
                    }
                }
            }
            Err(_) => futures::failed(JsonRpcError::invalid_params("Invalid JSON object")).boxed(),
        };

        io.add_async_method("backend_importWallet", import_callback);
    }

    let dir = chain
        .get_path("contracts".to_string())
        .expect("Expect directory for contracts");

    let contracts = Arc::new(Contracts::new(dir));

    {
        let contracts = contracts.clone();

        io.add_async_method("emerald_contracts",
                            move |_| futures::finished(Value::Array(contracts.list())).boxed());
    }

    {
        let contracts = contracts.clone();

        io.add_async_method("emerald_addContract", move |p| match p {
            Params::Array(ref vec) => {
                match contracts.add(&vec[0]) {
                    Ok(_) => futures::finished(Value::Bool(true)).boxed(),
                    Err(_) => futures::failed(JsonRpcError::new(ErrorCode::InternalError)).boxed(),
                }
            }
            _ => futures::failed(JsonRpcError::new(ErrorCode::InvalidParams)).boxed(),
        });
    }

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![cors::AccessControlAllowOrigin::Any,
                                                cors::AccessControlAllowOrigin::Null]))
        .start_http(addr)
        .expect("Expect to build HTTP RPC server");

    if log_enabled!(LogLevel::Info) {
        info!("Connector started on http://{}", server.address());
    }

    server.wait().expect("Expect to start HTTP RPC server");
}
