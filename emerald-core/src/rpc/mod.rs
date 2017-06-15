//! # JSON RPC module

mod http;
mod serialize;
mod error;


pub use self::error::Error;
use self::serialize::{RPCAccount, RPCTransaction};
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
use serde::Serialize;
use serde_json::{self, Map, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
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

fn to_value<T: Serialize>(value: T) -> Result<Value, JsonRpcError> {
    let result = serde_json::to_value(value);
    match result {
        Ok(value) => Ok(value),
        Err(_) => Err(JsonRpcError::internal_error()),
    }
}

/// Start an HTTP RPC endpoint
pub fn start(addr: &SocketAddr, base_path: Option<PathBuf>, sec_level: Option<KdfDepthLevel>) {
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
        io.add_method("emerald_currentVersion", move |p: Params| {
            let _: () = p.parse()?;
            to_value(::version())
        });
    }

    {
        io.add_method("emerald_heartbeat", move |p: Params| {
            let _: () = p.parse()?;
            to_value(get_time().sec)
        });
    }

    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum CallParams {
            PassOnly((String,)),
            WithAccount((RPCAccount, String)),
        }

        let sec = sec_level;
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_newAccount", move |p: Params| {
            let p: CallParams = p.parse()?;

            let (account, pass) = match p {
                CallParams::PassOnly((pass,)) => {
                    (RPCAccount {
                         name: "".to_string(),
                         description: "".to_string(),
                     },
                     pass)
                }
                CallParams::WithAccount((account, pass)) => (account, pass),
            };

            if pass.is_empty() {
                return Err(JsonRpcError::invalid_params("Empty passphrase"));
            }

            match KeyFile::new(&pass, &sec, Some(account.name), Some(account.description)) {
                Ok(kf) => {
                    let addr = kf.address.to_string();
                    match kf.flush(keystore_path.as_ref()) {
                        Ok(_) => {
                            to_value(addr)
                        }
                        Err(_) => {
                            Err(JsonRpcError::internal_error())
                        }
                    }
                }
                Err(_) => {
                    Err(JsonRpcError::invalid_params("Invalid Keyfile data format"))
                }
            }
        });
    }

    {
        let keystore_path = keystore_path.clone();

        io.add_method("emerald_signTransaction", move |p: Params| {
            let p: (RPCTransaction, String) = p.parse()?;

            let addr = Address::from_str(&p.0.from);
            if addr.is_err() {
                return Err(JsonRpcError::invalid_params("Empty address"));
            }
            let addr = addr.unwrap();

            match KeyFile::search_by_address(&addr, keystore_path.as_ref()) {
                Ok(kf) => {
                    if let Ok(pk) = kf.decrypt_key(&p.1) {
                        match p.0.try_into() {
                            Ok(tr) => {
                                to_value(tr.to_raw_params(pk, TESTNET_ID))
                            }
                            Err(err) => {
                                Err(JsonRpcError::invalid_params(err.to_string()))
                            }
                        }
                    } else {
                        Err(JsonRpcError::invalid_params("Invalid passphrase"))
                    }
                }
                Err(_) => {
                    Err(JsonRpcError::invalid_params("Can't find account"))
                }
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
