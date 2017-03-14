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
use std::ops::Add;
use std::sync::Arc;

use jsonrpc_core::IoHandler;
use jsonrpc_minihttp_server::{cors, DomainsValidation, ServerBuilder};

use log::LogLevel;

mod method;
mod request;
mod serialize;

pub fn start(addr: &SocketAddr, client_addr: &SocketAddr) {
    let mut io = IoHandler::default();

    let url = Arc::new(request::Wrapper {
                           url: request::StringWrapper {
                               str: "http://".to_string().add(&client_addr.to_string()),
                           },
                       });

    let web3_client_version = url.clone();

    io.add_async_method("web3_clientVersion",
                        move |_| web3_client_version.request(&method::Method::ClientVersion));

    let eth_syncing = url.clone();

    io.add_async_method("eth_syncing",
                        move |_| eth_syncing.request(&method::Method::EthSyncing));

    let eth_block_number = url.clone();

    io.add_async_method("eth_blockNumber",
                        move |_| eth_block_number.request(&method::Method::EthBlockNumber));

    let eth_accounts = url.clone();

    io.add_async_method("eth_accounts",
                        move |_| eth_accounts.request(&method::Method::EthAccounts));

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
