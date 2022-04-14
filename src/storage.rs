/*
Copyright 2019 ETCDEV GmbH
Copyright 2020 EmeraldPay, Inc

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
//!
//! # Access Vault Storage
//!
//! It's the main access point to access everything related to the Vault.
//!
//! ## Design
//!
//! * everything is stored in plain files encoded as Protobuf
//!     - See `proto` directory in the root of the project
//!     - Also see modules _convert_ and _proto_ for reading/writing data
//! * except the Addressbook, which is going to be removed later
//! * using the following types:
//!     - `global.key` - Global Key to encrypt/decrypt individual secrets
//!     - `<ID>.seed` - Seed Key. I.e., source for multiple keys used by different wallets
//!     - `<ID>.key` - A single Secret Key
//!     - `<ID>.wallet` - Wallet definition. References a key from _seed_ or _single key_ file.
//! * each _ID_ is a random UUID
//! * secrets are encrypted with AES-128
//!     - default KDF is Aragon2
//!     - but for backward compatibility also PBKDF2 and Scrypt are supported, but not used to create new secrets
//! * when an item in the vault is updated (ex. a wallet gets new title set by user), then an old version of the file is moved to the `.archive` subdir, under subdir with current timestamp
//!     - technically it allows to recover to an old state
//! * each Wallet file may contain multiple _Entries_
//!     - Wallet Entry is actual configuration for Blockchain + Address/Key
//!
//!

pub mod addressbook;
pub mod archive;
pub mod entry;
pub(crate) mod vault_ethereum;
pub(crate) mod vault_bitcoin;
pub mod vault;
pub mod global_key;
pub mod admin;

use std::{
    env,
    path::{Path, PathBuf},
};

/// Base dir for internal data, all chain-related should be store in subdirectories
#[derive(Debug, Clone)]
pub struct Storages {
    /// base dir
    base_dir: PathBuf,
}

/// Default path (*nix)
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
pub fn default_path() -> PathBuf {
    let mut config_dir = env::home_dir().expect("Expect path to home dir");
    config_dir.push(".emerald");
    config_dir
}

/// Default path (Mac OS X)
#[cfg(target_os = "macos")]
pub fn default_path() -> PathBuf {
    let mut config_dir = env::home_dir().expect("Expect path to home dir");
    config_dir.push("Library");
    config_dir.push("Emerald");
    config_dir
}

/// Default path (Windows OS)
#[cfg(target_os = "windows")]
pub fn default_path() -> PathBuf {
    let app_data_var = env::var("APPDATA").expect("Expect 'APPDATA' environment variable");
    let mut config_dir = PathBuf::from(app_data_var);
    config_dir.push(".emerald");
    config_dir
}

/// Build `chain` specific path for selected `folder`
///
/// # Arguments:
///
/// * `base_path` - base folder for storage
/// * `chain` - chain name
/// * `folder` - destination folder
///
pub fn build_path(base_path: &Path, chain: &str, folder: &str) -> PathBuf {
    let mut path = PathBuf::from(base_path);
    path.push(chain);
    path.push(folder);
    path
}
