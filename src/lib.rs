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
extern crate hyper;
extern crate reqwest;


use jsonrpc_core::IoHandler;
use jsonrpc_minihttp_server::{cors, DomainsValidation, ServerBuilder};

use log::LogLevel;
use std::net::SocketAddr;
use std::sync::Arc;

mod method;
mod request;
mod serialize;

pub fn start(addr: &SocketAddr, client_addr: &SocketAddr) {
    let mut io = IoHandler::default();

    let url = Arc::new(request::AsyncWrapper::new(&format!("http://{}", client_addr)));

    let web3_client_version = url.clone();

    io.add_async_method("web3_clientVersion",
                        move |p| web3_client_version.request(&method::Method::ClientVersion(&p)));

    let eth_syncing = url.clone();

    io.add_async_method("eth_syncing",
                        move |p| eth_syncing.request(&method::Method::EthSyncing(&p)));

    let eth_block_number = url.clone();

    io.add_async_method("eth_blockNumber",
                        move |p| eth_block_number.request(&method::Method::EthBlockNumber(&p)));

    let eth_accounts = url.clone();

    io.add_async_method("eth_accounts",
                        move |p| eth_accounts.request(&method::Method::EthAccounts(&p)));

    let eth_get_balance = url.clone();

    io.add_async_method("eth_getBalance",
                        move |p| eth_get_balance.request(&method::Method::EthGetBalance(&p)));

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
