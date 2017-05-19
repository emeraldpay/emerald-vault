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
extern crate futures_cpupool;
extern crate regex;

use docopt::Docopt;
use emerald::storage::default_path;
use env_logger::LogBuilder;
use futures_cpupool::CpuPool;
use log::{LogLevel, LogLevelFilter};
use regex::Regex;
use std::{env, fs, io};
use std::ffi::OsStr;
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
    flag_client_path: String,
    flag_base_path: String,
}

fn launch_node<C: AsRef<OsStr>>(cmd: C) -> io::Result<Child> {
    Command::new(cmd)
        .args(&["--testnet", "--fast"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
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

    let node_path = args.flag_client_path
        .parse::<String>()
        .expect("Expect to parse path to node executable");

    let np = if !node_path.is_empty() {
        PathBuf::from(&node_path)
    } else {
        let re = Regex::new(r".+?geth").unwrap();
        let path = env::var("PATH").expect("Expect to get PATH variable");
        let p: Vec<&str> = path.split(":").filter(|s| re.is_match(s)).collect();
        PathBuf::from(p[0])
    };

    let mut log = default_path();
    log.push("log");
    if fs::create_dir_all(log.as_path()).is_ok() {};

    log.push("geth_log.txt");
    let mut log_file = match fs::File::create(log.as_path()) {
        Ok(f) => f,
        Err(err) => {
            error!("Unable to open node log file: {}", err);
            exit(1);
        }
    };

    let node = match launch_node(np.as_os_str()) {
        Ok(pr) => pr,
        Err(err) => {
            error!("Unable to launch Ethereum node: {}", err);
            exit(1);
        }
    };

    let pool = CpuPool::new_num_cpus();
    pool.spawn_fn(move || io::copy(&mut node.stderr.unwrap(), &mut log_file))
        .forget();

    emerald::rpc::start(&addr, &client_addr, base_path);
}
