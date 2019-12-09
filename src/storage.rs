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
//! # Storage for `KeyFiles` and `Contracts`

pub mod addressbook;
pub mod keyfile;
pub mod vault;
pub mod error;
pub mod archive;

use std::env;
use std::path::{Path, PathBuf};

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
