//! Ethereum classic connector written in Rust.

#![warn(missing_docs)]

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#[macro_use]
extern crate log;
extern crate env_logger;

#[macro_use]
extern crate lazy_static;

extern crate futures;
extern crate jsonrpc_core;
extern crate jsonrpc_minihttp_server;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use jsonrpc_core::*;
use jsonrpc_core::futures::{BoxFuture, Future};
use jsonrpc_minihttp_server::*;

use log::LogLevel;

use serde::ser::{Serialize, Serializer};

static NODE_URL: &'static str = "http://127.0.0.1:8546";

enum Method<'a> {
    ClientVersion,
    EthSyncing,
    EthBlockNumber,
    EthAccounts,
    EthGetBalance(&'a Params),
}

impl<'a> Serialize for Method<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        match *self {
            Method::ClientVersion => serializer.serialize_some(&method("web3_clientVersion")),
            Method::EthSyncing => serializer.serialize_some(&method("eth_syncing")),
            Method::EthBlockNumber => serializer.serialize_some(&method("eth_blockNumber")),
            Method::EthAccounts => serializer.serialize_some(&method("eth_accounts")),
            Method::EthGetBalance(params) => {
                let p = match *params {
                    Params::Array(ref vec) => Params::Array(vec.clone()),
                    Params::Map(ref map) => Params::Map(map.clone()),
                    Params::None => Params::None,
                };

                serializer.serialize_some(&method_params("eth_getBalance", p))
            }
        }
    }
}

#[derive(Serialize, Debug)]
struct JsonData {
    jsonrpc: &'static str,
    method: &'static str,
    params: Params,
    id: usize,
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    env_logger::init().unwrap();

    start(&"127.0.0.1:8545".parse::<SocketAddr>().unwrap());
}

fn start(addr: &SocketAddr) {
    let mut io = IoHandler::default();

    io.add_async_method("web3_clientVersion", |p| web3_client_version(p));
    io.add_async_method("eth_syncing", |p| eth_syncing(p));
    io.add_async_method("eth_blockNumber", |p| eth_block_number(p));
    io.add_async_method("eth_accounts", |p| eth_accounts(p));
    io.add_async_method("eth_getBalance", |p| eth_get_balance(p));

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![cors::AccessControlAllowOrigin::Any,
                                                cors::AccessControlAllowOrigin::Null]))
        .start_http(addr)
        .expect("Unable to start RPC server");

    if log_enabled!(LogLevel::Info) {
        info!("Connector is started on {}", server.address());
    }

    server.wait().unwrap();
}

fn web3_client_version(_: Params) -> BoxFuture<Value, Error> {
    let client = reqwest::Client::new().unwrap();

    let mut res = client.post(NODE_URL)
        .json(&Method::ClientVersion)
        .send()
        .unwrap();

    let json: Value = res.json().unwrap();

    futures::finished(json["result"].clone()).boxed()
}

fn eth_syncing(_: Params) -> BoxFuture<Value, Error> {
    let client = reqwest::Client::new().unwrap();

    let mut res = client.post(NODE_URL)
        .json(&Method::EthSyncing)
        .send()
        .unwrap();

    let json: Value = res.json().unwrap();

    futures::finished(json["result"].clone()).boxed()
}

fn eth_block_number(_: Params) -> BoxFuture<Value, Error> {
    let client = reqwest::Client::new().unwrap();

    let mut res = client.post(NODE_URL)
        .json(&Method::EthBlockNumber)
        .send()
        .unwrap();

    let json: Value = res.json().unwrap();

    futures::finished(json["result"].clone()).boxed()
}

fn eth_accounts(_: Params) -> BoxFuture<Value, Error> {
    let client = reqwest::Client::new().unwrap();

    let mut res = client.post(NODE_URL)
        .json(&Method::EthAccounts)
        .send()
        .unwrap();

    let json: Value = res.json().unwrap();

    futures::finished(json["result"].clone()).boxed()
}

fn eth_get_balance(params: Params) -> BoxFuture<Value, Error> {
    let client = reqwest::Client::new().unwrap();

    let mut res = client.post(NODE_URL)
        .json(&Method::EthGetBalance(&params))
        .send()
        .unwrap();

    let json: Value = res.json().unwrap();

    futures::finished(json["result"].clone()).boxed()
}

fn method(method: &'static str) -> JsonData {
    method_params(method, Params::None)
}

lazy_static! {
    static ref REQ_ID: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(1));
}

fn method_params(method: &'static str, params: Params) -> JsonData {
    JsonData {
        jsonrpc: "2.0",
        method: method,
        params: params,
        id: REQ_ID.fetch_add(1, Ordering::SeqCst),
    }
}

#[cfg(test)]
mod tests {

    use super::method;

    #[test]
    fn method_test() {
        assert_eq!(method("xxx").id, 1);
    }
}
