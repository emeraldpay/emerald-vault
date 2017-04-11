//! # Ethereum classic web3 like connector library.

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#![deny(missing_docs)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate crypto;
extern crate futures;
extern crate glob;
extern crate jsonrpc_core;
extern crate jsonrpc_minihttp_server;
extern crate hyper;
extern crate regex;
extern crate reqwest;
extern crate rustc_serialize;
extern crate uuid;
extern crate secp256k1;
extern crate rand;

mod address;
pub mod keystore;
mod request;
mod serialize;
pub mod contracts;
mod storage;
mod key_generator;
pub mod rlp;
pub mod transaction;

use self::serde_json::Value;
pub use address::{ADDRESS_BYTES, Address};
use contracts::Contracts;
use jsonrpc_core::{Error, ErrorCode, IoHandler, Params};
use jsonrpc_core::futures::Future;
use jsonrpc_minihttp_server::{DomainsValidation, ServerBuilder, cors};
pub use keystore::{KeyFile, address_exists};

use log::LogLevel;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use storage::{ChainStorage, Storages};

/// RPC methods
pub enum Method {
    /// [web3_clientVersion](https://github.com/ethereum/wiki/wiki/JSON-RPC#web3_clientversion)
    ClientVersion,

    /// [eth_syncing](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_syncing)
    EthSyncing,

    /// [eth_blockNumber](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_blocknumber)
    EthBlockNumber,

    /// [eth_accounts](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_accounts)
    EthAccounts,

    /// [eth_getBalance](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getbalance)
    EthGetBalance,

    /// [eth_call](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_call)
    EthCall,

    /// `trace_call`
    TraceCall,

    /// `eth_getTransactionByHash`
    /// https://github.com/ethereumproject/wiki/wiki/JSON-RPC#eth_gettransactionbyhash
    GetTxByHash,

    /// `eth_getTransactionReceipt`
    /// https://github.com/ethereumproject/wiki/wiki/JSON-RPC#eth_gettransactionreceipt
    GetTxReceipt,
}

/// PRC method's parameters
pub struct MethodParams<'a>(pub Method, pub &'a Params);

/// Start an HTTP RPC endpoint
pub fn start(addr: &SocketAddr, client_addr: &SocketAddr, base_path: Option<&Path>) {
    let mut io = IoHandler::default();

    let url = Arc::new(request::AsyncWrapper::new(&format!("http://{}", client_addr)));

    {
        let url = url.clone();

        io.add_async_method("web3_clientVersion",
                            move |p| url.request(&MethodParams(Method::ClientVersion, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_syncing",
                            move |p| url.request(&MethodParams(Method::EthSyncing, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_blockNumber",
                            move |p| url.request(&MethodParams(Method::EthBlockNumber, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_accounts",
                            move |p| url.request(&MethodParams(Method::EthAccounts, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_getBalance",
                            move |p| url.request(&MethodParams(Method::EthGetBalance, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_getTransactionByHash",
                            move |p| url.request(&MethodParams(Method::GetTxByHash, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_call",
                            move |p| url.request(&MethodParams(Method::EthCall, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("trace_call",
                            move |p| url.request(&MethodParams(Method::TraceCall, &p)));
    }

    let storage = Storages::new(base_path);

    if storage.init().is_err() {
        panic!("Unable to initialize storage");
    }

    let chain = ChainStorage::new(&storage, "default".to_string());

    if chain.init().is_err() {
        panic!("Unable to initialize chain");
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

        io.add_async_method("emerald_addContract", move |p: Params| {
            let res = match p {
                Params::Array(ref vec) => {
                    match contracts.add(&vec[0]) {
                        Ok(_) => Ok(Value::Bool(true)),
                        Err(_) => Err(Error::new(ErrorCode::InternalError)),
                    }
                }
                _ => Err(Error::new(ErrorCode::InvalidParams)),
            };

            futures::done(res).boxed()
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
