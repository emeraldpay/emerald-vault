//! # CLI wrapper for Ethereum Classic web3 like connector

#![cfg(feature = "cli")]

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#[macro_use]
extern crate log;

extern crate docopt;
extern crate env_logger;
extern crate emerald_core as emerald;
extern crate regex;
extern crate rustc_serialize;

use docopt::Docopt;
use emerald::keystore::KdfDepthLevel;
use env_logger::LogBuilder;
use log::{LogLevel, LogLevelFilter};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::*;
use std::str::FromStr;

const USAGE: &'static str = include_str!("../../usage.txt");

#[derive(Debug, RustcDecodable)]
struct Args {
    flag_version: bool,
    flag_verbose: usize,
    flag_quiet: bool,
    flag_host: String,
    flag_port: String,
    flag_base_path: String,
    flag_security_level: String,
    cmd_server: bool,
    cmd_account: bool,
    cmd_transaction: bool,
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
        println!("v{}", emerald::version());
        exit(0);
    }

    if log_enabled!(LogLevel::Info) {
        info!("Starting Emerald Connector - v{}", emerald::version());
    }

    let sec_level: &str = &args.flag_security_level
                               .parse::<String>()
                               .expect("Expect to parse security level");
    let sec_level = match KdfDepthLevel::from_str(sec_level) {
        Ok(sec) => sec,
        Err(e) => {
            error!("{}", e.to_string());
            KdfDepthLevel::default()
        }
    };
    info!("security level set to '{}'", sec_level);

    if args.cmd_server {
        let addr = format!("{}:{}", args.flag_host, args.flag_port)
            .parse::<SocketAddr>()
            .expect("Expect to parse address");

        let base_path_str = args.flag_base_path
            .parse::<String>()
            .expect("Expect to parse base path");

        let base_path = if !base_path_str.is_empty() {
            Some(PathBuf::from(&base_path_str))
        } else {
            None
        };
        emerald::rpc::start(&addr, base_path, Some(sec_level));
    }

}
