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
//! # Core domain logic module

pub mod ethereum;
pub mod chains;
pub mod error;

pub use self::ethereum::address::{EthereumAddress, ETHEREUM_ADDRESS_BYTES};
pub use self::error::Error;
pub use self::ethereum::signature::{EthereumPrivateKey, EthereumSignature, ECDSA_SIGNATURE_BYTES, PRIVATE_KEY_BYTES};
pub use self::ethereum::transaction::EthereumTransaction;
