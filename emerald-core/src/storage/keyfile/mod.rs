//! # Storage for `KeyFiles`
///
/// Provides 2 variants of storage:
/// * backed with `db`
/// * plain filesystem
///

mod db;
mod fs;
mod error;

pub use self::db::DbStorage;
pub use self::error::Error as KeyStorageError;
pub use self::fs::{FsStorage, generate_filename};
use core::Address;
use keystore::KeyFile;


/// Short account info
///
#[derive(Debug, Clone, Default)]
pub struct AccountInfo {
    /// Address of account
    pub address: String,

    /// Optional name for account
    pub name: String,

    /// Optional description for account
    pub description: String,

    /// shows whether it is normal account or
    /// held by HD wallet
    pub is_hardware: bool,
}

/// Storage for KeyFiles
///
pub trait KeyfileStorage {
    /// Put new `KeyFile` inside storage
    ///
    /// # Arguments:
    ///
    ///  * kf - `KeyFile` to insert
    ///
    fn put(&self, kf: &KeyFile) -> Result<(), KeyStorageError>;

    /// Delete `KeyFile` from storage for specified `Address`
    ///
    /// # Arguments:
    ///
    ///  * addr - target `Address`
    ///
    fn delete(&self, addr: &Address) -> Result<(), KeyStorageError>;

    /// Search of `KeyFile` by specified `Address`
    ///
    /// # Arguments:
    ///
    ///  * addr - target `Address`
    ///
    fn search_by_address(&self, addr: &Address) -> Result<KeyFile, KeyStorageError>;

    /// Hides account for given address from being listed
    ///
    /// # Arguments:
    ///
    ///  * addr - target `Address`
    ///
    fn hide(&self, addr: &Address) -> Result<bool, KeyStorageError>;

    /// Unhides account for given address from being listed
    ///
    /// # Arguments:
    ///
    ///  * addr - target `Address`
    ///
    fn unhide(&self, addr: &Address) -> Result<bool, KeyStorageError>;

    /// Lists info for `Keystore` files inside storage
    /// Can include hidden files if flag set.
    ///
    /// # Arguments
    ///
    /// * `showHidden` - flag to show hidden `Keystore` files
    ///
    /// # Return:
    ///
    /// Array of `AccountInfo` struct
    ///
    fn list_accounts(&self, show_hidden: bool) -> Result<Vec<AccountInfo>, KeyStorageError>;
}
