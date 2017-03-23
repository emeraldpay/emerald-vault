//! CLI wrapper for ethereum classic web3 like connector.

#![cfg(feature = "cli")]

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

extern crate docopt;
extern crate env_logger;
extern crate rustc_serialize;

extern crate emerald;

use docopt::Docopt;
use std::env;
use std::net::SocketAddr;
use std::process::*;

const USAGE: &'static str = include_str!("../usage.txt");

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

#[derive(Debug, RustcDecodable)]
struct Args {
    flag_version: bool,
    flag_verbose: bool,
    flag_quiet: bool,
    flag_address: String,
    flag_client_address: String,
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    env_logger::init().expect("Expect to initialize logger");

    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!("v{}", VERSION.unwrap_or("unknown"));
        exit(0);
    }

    let addr = args.flag_address.parse::<SocketAddr>().expect("Expect to parse address");

    let client_addr =
        args.flag_client_address.parse::<SocketAddr>().expect("Expect to parse client address");

    println!("Starting Emerald Connector - v{}",
             VERSION.unwrap_or("unknown"));
    println!("Listen for connection on http://{}", addr);

    emerald::start(&addr, &client_addr);
}
