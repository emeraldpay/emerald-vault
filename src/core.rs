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
//! # Core domain logic module

pub mod address;
pub mod chains;
pub mod error;
pub mod signature;
pub mod transaction;

pub use self::address::{Address, ADDRESS_BYTES};
pub use self::error::Error;
pub use self::signature::{PrivateKey, Signature, ECDSA_SIGNATURE_BYTES, PRIVATE_KEY_BYTES};
pub use self::transaction::Transaction;
use super::util;
