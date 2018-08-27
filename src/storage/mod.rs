//! # Storage for `KeyFiles` and `Contracts`

pub mod addressbook;
mod contracts;
mod keyfile;
mod storage_ctrl;

pub use self::addressbook::error::AddressbookError;
pub use self::addressbook::AddressbookStorage;
pub use self::contracts::ContractStorage;
pub use self::keyfile::*;
pub use self::storage_ctrl::StorageController;
pub use self::KeystoreError;
use std::boxed::Box;
use std::env;
use std::fs;
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

/// Creates specific type of `KeyFile` storage (database or filesystem)
///
/// # Arguments:
///
/// * `keystore_path` - path for `KeyFile` storage
///
pub fn build_keyfile_storage<P>(path: P) -> Result<Box<KeyfileStorage>, KeystoreError>
where
    P: AsRef<Path>,
{
    #[cfg(feature = "default")]
    {
        let mut p = PathBuf::new();
        p.push(path);
        p.push(".db");
        match DbStorage::new(p) {
            Ok(db) => Ok(Box::new(db)),
            Err(_) => Err(KeystoreError::StorageError(
                "Can't create database Keyfile storage".to_string(),
            )),
        }
    }
    #[cfg(feature = "fs-storage")]
    match FsStorage::new(path) {
        Ok(fs) => Ok(Box::new(fs)),
        Err(_) => Err(KeystoreError::StorageError(
            "Can't create filesystem Keyfile storage".to_string(),
        )),
    }
}

/// Creates specific type of `Contract` storage (database or filesystem)
///
/// # Arguments:
///
/// * `path` - path for `Contract` storage
///
pub fn build_contract_storage<P>(path: P) -> Result<Box<ContractStorage>, KeystoreError>
where
    P: AsRef<Path>,
{
    // TODO: implement DB storage. Add conditional compilation.
    let mut p = PathBuf::new();
    p.push(path);
    fs::create_dir_all(&p)?;

    Ok(Box::new(ContractStorage::new(p)))
}

/// Creates specific type of `Addressbook` storage (database or filesystem)
///
/// # Arguments:
///
/// * `path` - path for `Addressbook` storage
///
pub fn build_addressbook_storage<P>(path: P) -> Result<Box<AddressbookStorage>, KeystoreError>
where
    P: AsRef<Path>,
{
    // TODO: implement DB storage. Add conditional compilation.
    let mut p = PathBuf::new();
    p.push(path);
    fs::create_dir_all(&p)?;

    Ok(Box::new(AddressbookStorage::new(p)))
}
