//! Ethereum classic intermediate connector written in Rust.

#![warn(missing_docs)]

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate futures;
extern crate jsonrpc_core;
extern crate jsonrpc_minihttp_server;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use std::env;
use std::net::SocketAddr;

use jsonrpc_core::*;
use jsonrpc_core::futures::{BoxFuture, Future};
use jsonrpc_minihttp_server::*;

use log::LogLevel;

use serde::ser::{Serialize, Serializer};

static NODE_URL: &'static str = "http://127.0.0.1:8546";

enum Method {
    ClientVersion,
    EthAccounts,
}

impl Serialize for Method {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        match *self {
            Method::ClientVersion => serializer.serialize_some(&method("web3_clientVersion")),
            Method::EthAccounts => serializer.serialize_some(&method("eth_accounts")),
        }
    }
}

#[derive(Serialize, Debug)]
struct JsonData {
    jsonrpc: &'static str,
    method: &'static str,
    params: Vec<&'static str>,
    id: u32,
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    env_logger::init().unwrap();

    /*
    let args: Vec<String> = ::std::env::args().collect();

    if args.len() >= 3 {
        match &args[1][..] {
            "client" => return client::main(),
            "server" => return server::main(),
            _ => ()
        }
    }

    println!("usage {} [--node <HOST>:<PORT>] [<HOST>:<PORT>]", args[0]);
    */

    start(&"127.0.0.1:8545".parse::<SocketAddr>().unwrap());
}

fn start(addr: &SocketAddr) {
    let mut io = IoHandler::default();

    io.add_async_method("web3_clientVersion", |p| web3_client_version(p));

    io.add_async_method("eth_accounts", |p| eth_accounts(p));

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![cors::AccessControlAllowOrigin::Any]))
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

fn eth_accounts(_: Params) -> BoxFuture<Value, Error> {
    let client = reqwest::Client::new().unwrap();

    let mut res = client.post(NODE_URL)
        .json(&Method::EthAccounts)
        .send()
        .unwrap();

    let json: Value = res.json().unwrap();

    futures::finished(json["result"].clone()).boxed()
}

fn method(method: &'static str) -> JsonData {
    JsonData {
        jsonrpc: "2.0",
        method: method,
        params: vec![],
        id: 1,
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
