//! # JSON RPC module

mod http;
mod serialize;
mod error;

use self::serialize::{RPCTransaction, RPCAccount};

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
use serde_json::{to_value, Map, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::str::FromStr;
use time::get_time;

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
    macro_rules! parse_params {
        ( $p:ident : $t:ty ) => (
            let $p: Result<$t, JsonRpcError> = $p.parse();
            if $p.is_err() {
                return futures::failed($p.err().unwrap()).boxed();
            }
            let $p = $p.unwrap();
        );
    }

    macro_rules! put_result {
        ( $p:expr ) => (
            let value = to_value($p);
            if value.is_err() {
                return futures::failed(JsonRpcError::internal_error()).boxed();
            }
            return futures::finished(value.unwrap()).boxed();
        )
    }

    macro_rules! put_error {
        ( $p:expr ) => (
            return futures::failed($p).boxed();
        )
    }

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
        io.add_async_method("emerald_currentVersion", move |p: Params| {
            parse_params!(p: ());
            put_result!(::version());
        });
    }

    {
        io.add_async_method("emerald_heartbeat", move |p: Params| {
            parse_params!(p: ());
            put_result!(get_time().sec);
        });
    }

    {
        let sec = sec_level;
        let keystore_path = keystore_path.clone();

        io.add_async_method("emerald_newAccount", move |p: Params| {
            parse_params!(p: (RPCAccount, String));
            if p.1.is_empty() {
                put_error!(JsonRpcError::invalid_params("Empty passphrase"));
            }
            match KeyFile::new(&p.1, &sec, Some(p.0.name), Some(p.0.description)) {
                Ok(kf) => {
                    let addr = kf.address.to_string();
                    match kf.flush(keystore_path.as_ref()) {
                        Ok(_) => { put_result!(addr); },
                        Err(_) => { put_error!(JsonRpcError::internal_error()); },
                    }
                },
                Err(_) => {
                    put_error!(JsonRpcError::invalid_params("Invalid Keyfile data \
                                                             format"));
                },
            }
        });
    }

    {
        let keystore_path = keystore_path.clone();

        io.add_async_method("emerald_signTransaction", move |p: Params| {
            parse_params!(p: (RPCTransaction, String));
            let addr = Address::from_str(&p.0.from);
            if addr.is_err() {
                put_error!(JsonRpcError::invalid_params("Invalid from address"));
            }
            let addr = addr.unwrap();

            match KeyFile::search_by_address(&addr, keystore_path.as_ref()) {
                Ok(kf) => {
                    if let Ok(pk) = kf.decrypt_key(&p.1) {
                        match p.0.try_into() {
                            Ok(tr) => {
                                put_result!(tr.to_raw_params(pk, TESTNET_ID));
                            },
                            Err(err) => {
                                put_error!(JsonRpcError::invalid_params(err.to_string()));
                            },
                        }
                    } else {
                        put_error!(JsonRpcError::invalid_params("Invalid passphrase"));
                    }
                },
                Err(_) => {
                    put_error!(JsonRpcError::invalid_params("Can't find account"));
                },
            }
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
