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
                                                      Value::String("latest".to_string())])))
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
                obj.insert("nonce".to_string(), Value::String(format!("{}", n)));

                return Ok(Params::Array(vec![Value::Object(obj)]));
            }
            _ => return Err(Error::InvalidDataFormat("Expected array of parameters".to_string())),
        }
    }

    Err(Error::InvalidDataFormat(format!("Invalid `nonce` value for: {}", addr)))
}

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

        io.add_async_method("net_version",
                            move |p| url.request(&MethodParams(ClientMethod::NetVersion, &p)));
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
                let accounts = list.iter()
                    .map(|&(ref k, ref v)| {
                             let mut m = Map::new();
                             m.insert("name".to_string(), Value::String(k.clone()));
                             m.insert("address".to_string(), Value::String(v.clone()));
                             Value::Object(m)
                         })
                    .collect();
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
        let keystore_path = keystore_path.clone();

        let callback = move |p| {
            let addr = match p {
                Params::Array(ref vec) => {
                    let mut s = vec.get(0);
                    if s.is_none() {
                        return futures::failed(JsonRpcError::invalid_params("Invalid parameters \
                                                                             structure"))
                                       .boxed();
                    }

                    s = s.unwrap().get("from");
                    if s.is_none() {
                        return futures::failed(JsonRpcError::invalid_params("Can't parse sender \
                                                                             address"))
                                       .boxed();
                    }
                    let from = s.unwrap().as_str();
                    if from.is_none() {
                        return futures::failed(JsonRpcError::invalid_params("Invalid sender \
                                                                             address format"))
                                       .boxed();
                    };

                    let addr = from.unwrap().parse::<Address>();
                    if addr.is_err() {
                        return futures::failed(JsonRpcError::invalid_params("Can't parse sender \
                                                                             address"))
                                       .boxed();
                    }
                    addr.unwrap()
                }
                _ => {
                    return futures::failed(JsonRpcError::invalid_params("Invalid JSON object"))
                               .boxed();
                }
            };

            let passphrase = match p {
                Params::Array(ref vec) => {
                    let s = vec[0].get("password");
                    if s.is_none() {
                        return futures::failed(JsonRpcError::invalid_params("Invalid parameters \
                                                                             structure"))
                                       .boxed();
                    }
                    let pass = s.unwrap().as_str();

                    if pass.is_none() {
                        return futures::failed(JsonRpcError::invalid_params("Invalid sender \
                                                                             address format"))
                                       .boxed();
                    };
                    pass.unwrap()
                }
                _ => {
                    return futures::failed(JsonRpcError::invalid_params("Invalid JSON object"))
                               .boxed();
                }
            };

            let params =
                match inject_nonce(url.clone(), &p, &addr) {
                    Ok(v) => v,
                    Err(e) => {
                        return futures::failed(JsonRpcError::invalid_params(
                            format!("Can't read `nonce` value: {}", e.to_string()))).boxed()
                    }
                };

            match KeyFile::search_by_address(&addr, keystore_path.as_ref()) {
                Ok(kf) => {
                    if let Ok(pk) = kf.decrypt_key(passphrase) {
                        match Transaction::try_from(&params) {
                            Ok(tr) => {
                                url.request(&MethodParams(ClientMethod::EthSendRawTransaction,
                                                          &tr.to_raw_params(pk, TESTNET_ID)))
                            }
                            Err(err) => {
                                futures::done(Err(JsonRpcError::invalid_params(err.to_string())))
                                    .boxed()
                            }
                        }
                    } else {
                        futures::failed(JsonRpcError::invalid_params("Invalid passphrase")).boxed()
                    }
                }

                Err(_) => {
                    futures::failed(JsonRpcError::invalid_params("Can't find account")).boxed()
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
        let callback = move |mut p| {
            match p {
                Params::Array(ref mut vec) => {
                    vec.push(Value::String("latest".to_string()));
                }
                _ => {
                    return futures::failed(JsonRpcError::invalid_params("Invalid JSON object"))
                               .boxed();
                }
            };

            url.request(&MethodParams(ClientMethod::EthTraceCall, &p))
        };

        io.add_async_method("eth_traceCall", callback);
    }

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
