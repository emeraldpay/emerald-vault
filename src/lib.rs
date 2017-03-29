//! Ethereum classic web3 like connector library.

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

extern crate futures;
extern crate jsonrpc_core;
extern crate jsonrpc_minihttp_server;
extern crate hyper;
extern crate regex;
extern crate reqwest;
extern crate tiny_keccak;
extern crate secp256k1;
extern crate num_bigint;
extern crate rand;

mod keystore;
mod request;
mod serialize;
mod sign;

use jsonrpc_core::{IoHandler, Params};
use jsonrpc_minihttp_server::{cors, DomainsValidation, ServerBuilder};
pub use keystore::address_exists;

use log::LogLevel;
use std::net::SocketAddr;
use std::sync::Arc;

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
}

/// PRC method's parameters
pub struct MethodParams<'a>(pub Method, pub &'a Params);

/// Start an HTTP RPC endpoint
pub fn start(addr: &SocketAddr, client_addr: &SocketAddr) {
    let mut io = IoHandler::default();

    let url = Arc::new(request::AsyncWrapper::new(&format!("http://{}", client_addr)));

    let web3_client_version = url.clone();

    io.add_async_method("web3_clientVersion", move |p| {
        web3_client_version.request(&MethodParams(Method::ClientVersion, &p))
    });

    let eth_syncing = url.clone();

    io.add_async_method("eth_syncing",
                        move |p| eth_syncing.request(&MethodParams(Method::EthSyncing, &p)));

    let eth_block_number = url.clone();

    io.add_async_method("eth_blockNumber", move |p| {
        eth_block_number.request(&MethodParams(Method::EthBlockNumber, &p))
    });

    let eth_accounts = url.clone();

    io.add_async_method("eth_accounts",
                        move |p| eth_accounts.request(&MethodParams(Method::EthAccounts, &p)));

    let eth_get_balance = url.clone();

    io.add_async_method("eth_getBalance", move |p| {
        eth_get_balance.request(&MethodParams(Method::EthGetBalance, &p))
    });

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![cors::AccessControlAllowOrigin::Any,
                                                cors::AccessControlAllowOrigin::Null]))
        .start_http(addr)
        .expect("Expect to build HTTP RPC server");

    if log_enabled!(LogLevel::Info) {
        info!("Connector is started on {}", server.address());
    }

    server.wait().expect("Expect to start HTTP RPC server");
}
