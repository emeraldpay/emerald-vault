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
//! # Storage for `KeyFiles`
///
/// Provides 2 variants of storage:
/// * backed with `db`
/// * plain filesystem
///
mod db;
mod error;
mod fs;

pub use self::db::DbStorage;
pub use self::error::KeystoreError;
pub use self::fs::FsStorage;
use crate::core::Address;
use crate::keystore::{CryptoType, KeyFile};
use crate::util;
use crate::convert::proto::wallet::{Wallet, PKType};
use crate::convert::proto::types::HasUuid;
use hex::ToHex;

/// Short account info
///
#[derive(Debug, Clone, Default)]
#[deprecated]
pub struct AccountInfo {
    /// File name for `KeyFile`
    pub filename: String,

    /// Address of account
    pub address: String,

    /// Optional name for account
    pub name: String,

    /// Optional description for account
    pub description: String,

    /// shows whether it is normal account or
    /// held by HD wallet
    #[deprecated]
    pub is_hardware: bool,

    /// show if account hidden from 'normal' listing
    /// `normal` - not forcing to show hidden accounts
    #[deprecated]
    pub is_hidden: bool,
}

impl From<Wallet> for AccountInfo {
    fn from(wallet: Wallet) -> Self {
        AccountInfo {
            filename: wallet.get_id().to_string(),
            address: match wallet.accounts.first() {
                Some(acc) => {
                    acc.address.map(|a| a.to_string()).unwrap_or("".to_string())
                },
                None => "".to_string()
            },
            name: match wallet.label {
                Some(s) => s,
                None => "".to_string()
            },
            description: "".to_string(),
            is_hardware: false,
            is_hidden: false
        }
    }
}

impl From<KeyFile> for AccountInfo {
    fn from(kf: KeyFile) -> Self {
        let mut info = Self::default();
        info.address = kf.address.to_string();

        if let Some(name) = kf.name {
            info.name = name;
        };

        if let Some(desc) = kf.description {
            info.description = desc;
        };

        if let Some(visible) = kf.visible {
            info.is_hidden = !visible;
        };

        info.is_hardware = match kf.crypto {
            CryptoType::Core(_) => false,
            CryptoType::HdWallet(_) => true,
        };

        info
    }
}

#[deprecated]
/// Storage for `KeyFiles`
///
pub trait KeyfileStorage: Send + Sync {
    /// Put new `KeyFile` inside storage
    ///
    /// # Arguments:
    ///
    ///  * kf - `KeyFile` to insert
    ///
    fn put(&self, kf: &KeyFile) -> Result<(), KeystoreError>;

    /// Delete `KeyFile` from storage for specified `Address`
    ///
    /// # Arguments:
    ///
    ///  * addr - target `Address`
    ///
    fn delete(&self, addr: &Address) -> Result<(), KeystoreError>;

    /// Hide account for given address from being listed
    ///
    /// # Arguments:
    ///
    ///  * addr - target `Address`
    ///
    fn hide(&self, addr: &Address) -> Result<bool, KeystoreError>;

    /// Unhide account for given address from being listed
    ///
    /// # Arguments:
    ///
    ///  * addr - target `Address`
    ///
    fn unhide(&self, addr: &Address) -> Result<bool, KeystoreError>;

    /// Update account for given address with new name and description
    ///
    /// # Arguments:
    ///
    ///  * addr - target `Address`
    ///  * name - optional new name
    ///  * desc - optional new description
    ///
    fn update(
        &self,
        addr: &Address,
        name: Option<String>,
        desc: Option<String>,
    ) -> Result<(), KeystoreError>;

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
    fn list_accounts(&self, show_hidden: bool) -> Result<Vec<AccountInfo>, KeystoreError>;

    /// Search of `KeyFile` by specified `Address`
    /// Provides additional meta info for account
    ///
    /// # Arguments:
    ///
    ///  * addr - target `Address`
    ///
    fn search_by_address(&self, addr: &Address) -> Result<(AccountInfo, KeyFile), KeystoreError>;

    /// Check whether specified address is already
    /// inserted into the storage
    ///
    /// # Arguments
    ///
    /// * `addr` - address to check
    ///
    fn is_addr_exist(&self, addr: &Address) -> Result<(), KeystoreError> {
        match self.search_by_address(addr) {
            Ok((_, _)) => Ok(()),
            Err(e) => match e {
                KeystoreError::NotFound(_) => Err(KeystoreError::StorageError(format!(
                    "Address {} not in a storage",
                    addr
                ))),
                _ => Err(e),
            },
        }
    }
}

/// Creates filename for keystore file in format:
/// `UTC--yyy-mm-ddThh-mm-ssZ--uuid`
///
/// # Arguments
///
/// * `uuid` - UUID for keyfile
///
pub fn generate_filename(uuid: &str) -> String {
    format!("UTC--{}Z--{}", &util::timestamp(), &uuid)
}
