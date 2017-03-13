//! Ethereum classic web3 like connector library.

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#![deny(clippy, clippy_pedantic)]
#![allow(missing_docs_in_private_items, unknown_lints)]

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
extern crate reqwest;

use std::net::SocketAddr;

use jsonrpc_core::*;
use jsonrpc_minihttp_server::*;

use log::LogLevel;

mod method;
mod request;
mod serialize;

pub fn start(addr: &SocketAddr) {
    let mut io = IoHandler::default();

    io.add_async_method("web3_clientVersion",
                        |_| request::request(&method::Method::ClientVersion));
    io.add_async_method("eth_syncing",
                        |_| request::request(&method::Method::EthSyncing));
    io.add_async_method("eth_blockNumber",
                        |_| request::request(&method::Method::EthBlockNumber));
    io.add_async_method("eth_accounts",
                        |_| request::request(&method::Method::EthAccounts));
    io.add_async_method("eth_getBalance",
                        |p| request::request(&method::Method::EthGetBalance(&p)));

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![cors::AccessControlAllowOrigin::Any,
                                                cors::AccessControlAllowOrigin::Null]))
        .start_http(addr)
        .expect("Unable to start RPC server");

    if log_enabled!(LogLevel::Info) {
        info!("Connector is started on {}", server.address());
    }

    server.wait().expect("Unable to start server");
}
