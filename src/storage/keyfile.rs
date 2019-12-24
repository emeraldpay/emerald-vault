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
use crate::{
    structs::{
        types::HasUuid,
        wallet::{Wallet}
    }
};

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
