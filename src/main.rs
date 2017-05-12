//! # CLI wrapper for ethereum classic web3 like connector

#![cfg(feature = "cli")]

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#[macro_use]
extern crate log;

extern crate docopt;
extern crate env_logger;
extern crate emerald;
extern crate rustc_serialize;

use docopt::Docopt;
use emerald::storage::default_path;
use env_logger::LogBuilder;
use log::{LogLevel, LogLevelFilter};
use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::*;

const USAGE: &'static str = include_str!("../usage.txt");

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

#[derive(Debug, RustcDecodable)]
struct Args {
    flag_version: bool,
    flag_verbose: bool,
    flag_quiet: bool,
    flag_host: String,
    flag_port: String,
    flag_client_host: String,
    flag_client_port: String,
    flag_base_path: String,
}

fn launch_node(path: Option<PathBuf>) -> io::Result<Child> {
    let np = match path {
        Some(p) => p,
        None => {
            let mut p = default_path();
            p.push("bin");
            p.push("geth");
            p
        }
    };

    Command::new(np.as_path().as_os_str())
        .args(&["--testnet", "--fast"])
        .stdo   ut(Stdio::null())
        .spawn()
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

    let addr = format!("{}:{}", args.flag_host, args.flag_port)
        .parse::<SocketAddr>()
        .expect("Expect to parse address");

    let client_addr = format!("{}:{}", args.flag_client_host, args.flag_client_port)
        .parse::<SocketAddr>()
        .expect("Expect to parse client address");

    let base_path_str = args.flag_base_path
        .parse::<String>()
        .expect("Expect to parse base path");

    let base_path = if !base_path_str.is_empty() {
        Some(PathBuf::from(&base_path_str))
    } else {
        None
    };

    if log_enabled!(LogLevel::Info) {
        info!("Starting Emerald Connector - v{}",
              VERSION.unwrap_or("unknown"));
    }

    let mut node = match launch_node(None) {
        Ok(pr) => pr,
        Err(err) => {
            if log_enabled!(LogLevel::Error) {
                error!("Unable to launch Ethereum node: {}", err);
            }
            exit(1);
        }
    };

    emerald::rpc::start(&addr, &client_addr, base_path);
    node.kill().ok();
}
