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
extern crate futures;

use docopt::Docopt;
use emerald::storage::default_path;
use env_logger::LogBuilder;
use futures::future::Future;
use futures_cpupool::CpuPool;
use log::{LogLevel, LogLevelFilter};
use std::{env, fs, io};
use std::ffi::OsStr;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process::*;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

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

/// Launches  node in child process
fn launch_node<I, C>(cmd: &OsStr, out: Stdio, err: Stdio, args: I) -> io::Result<Child>
    where I: IntoIterator<Item = C>,
          C: AsRef<OsStr>
{
    Command::new(cmd)
        .args(args)
        .stdout(out)
        .stderr(err)
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

    // TODO: extract node logic into separate mod
    let mut log = default_path();
    log.push("log");
    if fs::create_dir_all(log.as_path()).is_ok() {};

    log.push("geth_log.txt");
    let mut f = match fs::File::create(log.as_path()) {
        Ok(f) => f,
        Err(err) => {
            error!("Unable to open node log file: {}", err);
            exit(1);
        }
    };

    let mut ndp = default_path();
    ndp.push("bin");
    ndp.push("geth");

    let log_file = Arc::new(Mutex::new(f));
    let node_path = Arc::new(Mutex::new(ndp));

    let guard_lf = log_file.lock().unwrap();
    let l_f = match guard_lf.try_clone() {
        Ok(f) => f,
        Err(e) => {
            error!("Node restart: can't redirect stdio: {}", e);
            exit(1);
        }
    };

    let out = unsafe { Stdio::from_raw_fd(l_f.as_raw_fd()) };
    let err = unsafe { Stdio::from_raw_fd(l_f.as_raw_fd()) };

    let guard_np = node_path.lock().unwrap();
    let node = match launch_node(guard_np.as_os_str(), out, err, &["--fast"]) {
        Ok(pr) => Arc::new(Mutex::new(pr)),
        Err(err) => {
            error!("Unable to launch Ethereum node: {}", err);
            exit(1);
        }
    };

    drop(guard_lf);
    drop(guard_np);

    let (tx, rx) = mpsc::channel();
    {
        let nd = node.clone();
        let lf = log_file.clone();
        let np = node_path.clone();

        let restart = move |chain: &str| {
            let mut n = nd.lock().unwrap();
            n.kill().expect("Expect to kill node");

            let l_f = match lf.lock().unwrap().try_clone() {
                Ok(f) => f,
                Err(e) => {
                    error!("Node restart: can't redirect stdio: {}", e);
                    exit(1);
                }
            };

            let out = unsafe { Stdio::from_raw_fd(l_f.as_raw_fd()) };
            let err = unsafe { Stdio::from_raw_fd(l_f.as_raw_fd()) };

            let res = match chain {
                "TESTNET" => {
                    launch_node(np.lock().unwrap().as_os_str(),
                                out,
                                err,
                                &["--testnet", "--fast"])
                }
                "MAINNET" | _ => launch_node(np.lock().unwrap().as_os_str(), out, err, &["--fast"]),
            };

            *n = match res {
                Ok(n) => n,
                Err(e) => {
                    error!("Can't restart node: {}", e);
                    exit(1);
                }
            };
        };

        thread::spawn(move || loop {
                          let chain: String = match rx.recv() {
                              Ok(s) => s,
                              Err(e) => {
                                  error!("Can't switch node chain: {}", e);
                                  exit(1);
                              }
                          };
                          restart(&chain);
                      });
    };

    emerald::rpc::start(&addr, &client_addr, base_path, tx.clone());
}
