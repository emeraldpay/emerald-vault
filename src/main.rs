//! CLI wrapper for ethereum classic web3 like connector.

#![cfg(feature = "cli")]

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#![deny(clippy, clippy_pedantic)]
#![allow(missing_docs_in_private_items, unknown_lints)]

extern crate env_logger;

extern crate emerald;

use std::env;
use std::net::SocketAddr;

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    env_logger::init().expect("Unable to initialize logger");

    emerald::start(&"127.0.0.1:8545".parse::<SocketAddr>().expect("Unable to parse address"));
}
