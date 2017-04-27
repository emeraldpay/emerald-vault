//! # Ethereum classic web3 like connector library

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#![deny(missing_docs)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate chrono;
extern crate crypto;
extern crate futures;
extern crate glob;
extern crate jsonrpc_core;
extern crate jsonrpc_minihttp_server;
extern crate hyper;
extern crate rand;
extern crate regex;
extern crate reqwest;
extern crate rustc_serialize;
extern crate secp256k1;
extern crate uuid;

mod core;
pub mod keystore;
pub mod contract;
pub mod storage;
pub mod rpc;
mod util;

pub use self::core::*;
pub use self::util::*;

#[cfg(test)]
mod tests {
    pub use super::*;
    pub use regex::Regex;
    pub use rustc_serialize::hex::{FromHex, ToHex};
    pub use rustc_serialize::json;
}
