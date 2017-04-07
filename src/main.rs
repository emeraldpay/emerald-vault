//! # CLI wrapper for ethereum classic web3 like connector.

#![cfg(feature = "cli")]

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate docopt;
extern crate rustc_serialize;

extern crate emerald;

use docopt::Docopt;
use env_logger::LogBuilder;
use log::{LogLevel, LogLevelFilter};
use std::env;
use std::net::SocketAddr;
use std::process::*;
use std::path::Path;

const USAGE: &'static str = include_str!("../usage.txt");

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

#[derive(Debug, RustcDecodable)]
struct Args {
    flag_version: bool,
    flag_verbose: bool,
    flag_quiet: bool,
    flag_address: String,
    flag_client_address: String,
    flag_base_path: String,
    flag_key_path: String,
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    let mut log_builder = LogBuilder::new();

    log_builder.filter(None, LogLevelFilter::Info);

    if env::var("RUST_LOG").is_ok() {
        log_builder.parse(&env::var("RUST_LOG").unwrap());
    }

    log_builder.init().expect("Expect to initialize logger");

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!("v{}", VERSION.unwrap_or("unknown"));
        exit(0);
    }

    let addr = args.flag_address
        .parse::<SocketAddr>()
        .expect("Expect to parse address");

    let client_addr = args.flag_client_address
        .parse::<SocketAddr>()
        .expect("Expect to parse client address");

    let base_path_str = args.flag_base_path
        .parse::<String>()
        .expect("Expect to parse base path");
    let base_path;
    if !base_path_str.is_empty() {
        base_path = Some(Path::new(&base_path_str));
    } else {
        base_path = None;
    }

    let key_path_str = args.flag_key_path
        .parse::<String>()
        .expect("Expect to parse key path");
    let key_path;
    if !key_path_str.is_empty() {
        key_path = Some(Path::new(&key_path_str));
    } else {
        key_path = None;
    }

    if log_enabled!(LogLevel::Info) {
        info!("Starting Emerald Connector - v{}",
              VERSION.unwrap_or("unknown"));
    }

    emerald::start(&addr, &client_addr, base_path, key_path);
}
