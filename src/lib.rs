#![feature(proc_macro, wasm_custom_section, wasm_import_module)]
extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

//! # Ethereum Classic web3 like connector library
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
#![deny(missing_docs)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

extern crate bitcoin;
extern crate byteorder;
extern crate chrono;
extern crate crypto;
extern crate emerald_rocksdb as rocksdb;
extern crate ethabi;
extern crate glob;
extern crate hex;
extern crate hidapi;
extern crate jsonrpc_core;
extern crate jsonrpc_http_server;
extern crate num;
extern crate rand;
extern crate regex;
extern crate reqwest;
#[cfg(all(unix))]
extern crate rust_scrypt;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;
extern crate time;
extern crate uuid;

mod contract;
mod core;
mod hdwallet;
pub mod keystore;
pub mod mnemonic;
pub mod rpc;
pub mod storage;
mod util;

#[wasm_bindgen]
pub use self::core::*;

#[wasm_bindgen]
pub use self::rpc::start;
#[wasm_bindgen]
pub use self::util::*;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// Get the current Emerald version.
#[wasm_bindgen]
pub fn version() -> &'static str {
    VERSION.unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    pub use super::*;
    pub use hex::{FromHex, ToHex};
    pub use regex::Regex;
}
