/*
Copyright 2019 ETCDEV GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//! # Ethereum web3 like connector library
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
//#![deny(missing_docs)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate enum_display_derive;

extern crate aes_ctr;
extern crate bitcoin;
extern crate byteorder;
extern crate chrono;
extern crate rocksdb;
extern crate ethabi;
extern crate glob;
extern crate hex;
extern crate hidapi;
extern crate hmac;
extern crate num;
extern crate pbkdf2;
extern crate rand;
extern crate regex;
extern crate scrypt;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;
extern crate sha2;
extern crate sha3;
extern crate time;
extern crate uuid;
extern crate protobuf;
extern crate csv;

#[macro_use]
pub mod util;
pub mod core;
pub mod hdwallet;
pub mod mnemonic;
pub mod storage;
pub mod convert;
pub mod crypto;
pub mod migration;
pub mod proto;
pub mod structs;

pub use self::core::*;
pub use self::util::*;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// Get the current Emerald version.
pub fn version() -> &'static str {
    VERSION.unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    pub use super::*;
    pub use hex::{FromHex, ToHex};
    pub use regex::Regex;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::fs::DirEntry;
    use log::Level;
    use crate::storage::archive::ARCHIVE_DIR;

    pub fn init_tests() {
        simple_logger::init_with_level(Level::Debug);
    }

    pub fn read_dir_fully<P: AsRef<Path>>(path: P) -> Vec<DirEntry> {
        fs::read_dir(path)
            .unwrap()
            .map(|i| i.unwrap())
            .collect()
    }

    pub fn get_archived<P: AsRef<Path>>(dir: P) -> Option<PathBuf> {
        let in_arch: Vec<DirEntry> = read_dir_fully(dir.as_ref().to_path_buf().join(ARCHIVE_DIR));
        if in_arch.len() != 1 {
            warn!("There're {} elements in archive", in_arch.len());
            return None;
        }
        let arch_dir = in_arch.first().unwrap();
        Some(arch_dir.path())
    }
}
