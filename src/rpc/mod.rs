//! # JSON RPC module

mod http;
mod serialize;
mod error;

pub use self::error::Error;
use super::addressbook::Addressbook;
use super::contract::Contracts;
use super::core::{self, Address, Transaction};
use super::keystore::{KdfDepthLevel, KeyFile, list_accounts};
use super::storage::{ChainStorage, Storages, default_keystore_path};
use super::util::{ToHex, align_bytes, to_arr, to_u64, trim_hex};
use futures;
use jsonrpc_core::{Error as JsonRpcError, ErrorCode, IoHandler, Params};
use jsonrpc_core::futures::Future;
use jsonrpc_minihttp_server::{DomainsValidation, ServerBuilder, cors};
use log::LogLevel;
use rustc_serialize::json;
use serde_json::{Map, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Main chain id
pub const MAINNET_ID: u8 = 61;

/// Test chain id
pub const TESTNET_ID: u8 = 62;

/// RPC methods
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ClientMethod {
    /// [web3_clientVersion](https://github.com/ethereum/wiki/wiki/JSON-RPC#web3_clientversion)
    Version,

    /// [net_version](https://github.com/ethereum/wiki/wiki/JSON-RPC#net_version)
    NetVersion,

    /// [eth_syncing](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_syncing)
    EthSyncing,

    /// [eth_blockNumber](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_blocknumber)
    EthBlockNumber,

    /// [eth_gasPrice](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gasprice)
    EthGasPrice,

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

fn inject_nonce(url: Arc<http::AsyncWrapper>, p: &Params, addr: &Address) -> Result<Params, Error> {
    let nonce = url.request(&MethodParams(ClientMethod::EthGetTxCount,
                                          &Params::Array(vec![Value::String(addr.to_string()),
                                                              Value::String("latest"
                                                                                .to_string())])))
        .wait()?;

    if let Some(n) = nonce.as_str() {
        match *p {
            Params::Array(ref vec) => {
                let v = vec.get(0).and_then(|v| v.as_object());
                if v.is_none() {
                    return Err(Error::InvalidDataFormat("Expected transaction formatted in JSON"
                                                            .to_string()));
                }

                let mut obj = v.unwrap().clone();
                obj.insert("nonce".to_string(), Value::String(n.to_string()));

                return Ok(Params::Array(vec![Value::Object(obj)]));
            }
            _ => return Err(Error::InvalidDataFormat("Expected array of parameters".to_string())),
        }
    }

    Err(Error::InvalidDataFormat(format!("Invalid `nonce` value for: {}", addr)))
}

/// Start an HTTP RPC endpoint
pub fn start(addr: &SocketAddr,
             base_path: Option<PathBuf>,
             sec_level: Option<KdfDepthLevel>) {
    let sec_level = sec_level.unwrap_or(KdfDepthLevel::default());

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
        let sec = sec_level;
        let keystore_path = keystore_path.clone();
        let callback = move |p| match Params::parse::<Value>(p) {
            Ok(ref v) => {
                let data = v.get(0);
                if data.is_none() {
                    return futures::failed(JsonRpcError::invalid_params("Invalid JSON object"))
                               .boxed();
                }
                let p = data.unwrap();
                if p.get("password").is_none() {
                    return futures::failed(JsonRpcError::invalid_params("Empty passphrase"))
                               .boxed();
                }

                let p_str = p.get("password").unwrap().as_str();
                if p_str.is_none() {
                    return futures::failed(JsonRpcError::invalid_params("Invalid passphrase \
                                                                         format"))
                                   .boxed();
                }

                let name = p.get("name")
                    .map(|n| {
                             if n.as_str().is_some() {
                                 return Some(n.as_str().unwrap().to_string());
                             }
                             None
                         })
                    .unwrap_or(None);

                let description = p.get("description")
                    .map(|d| {
                             if d.as_str().is_some() {
                                 return Some(d.as_str().unwrap().to_string());
                             }
                             None
                         })
                    .unwrap_or(None);

                match KeyFile::new(&p_str.unwrap(), &sec, name, description) {
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

        io.add_async_method("personal_newAccount", callback);
    }

    {
        let keystore_path = keystore_path.clone();
        let callback = move |p| match Params::parse::<Value>(p) {
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

        io.add_async_method("backend_importWallet", callback);
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

    let address_dir = chain
        .get_path("addressbook".to_string())
        .expect("Expect directory for address book");

    let addressbook = Arc::new(Addressbook::new(address_dir));

    {
        let addressbook = addressbook.clone();

        io.add_async_method("emerald_addressBook",
                            move |_| futures::finished(Value::Array(addressbook.list())).boxed());
    }

    {
        let addressbook = addressbook.clone();

        io.add_async_method("emerald_addAddress", move |p| match p {
            Params::Array(ref vec) => {
                match addressbook.add(&vec[0]) {
                    Ok(_) => futures::finished(Value::Bool(true)).boxed(),
                    Err(_) => futures::failed(JsonRpcError::new(ErrorCode::InternalError)).boxed(),
                }
            }
            _ => futures::failed(JsonRpcError::new(ErrorCode::InvalidParams)).boxed(),
        });
    }

    {
        let addressbook = addressbook.clone();

        io.add_async_method("emerald_updateAddress", move |p| match p {
            Params::Array(ref vec) => {
                match addressbook.edit(&vec[0]) {
                    Ok(_) => futures::finished(Value::Bool(true)).boxed(),
                    Err(_) => futures::failed(JsonRpcError::new(ErrorCode::InternalError)).boxed(),
                }
            }
            _ => futures::failed(JsonRpcError::new(ErrorCode::InvalidParams)).boxed(),
        });
    }

    {
        let addressbook = addressbook.clone();

        io.add_async_method("emerald_deleteAddress", move |p| match p {
            Params::Array(ref vec) => {
                match addressbook.delete(&vec[0]) {
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
