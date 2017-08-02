//! # Core domain logic module

mod address;
mod error;
mod signature;
mod transaction;
mod contract;

pub use self::address::{ADDRESS_BYTES, Address};
pub use self::error::Error;
pub use self::signature::{ECDSA_SIGNATURE_BYTES, PRIVATE_KEY_BYTES, PrivateKey, Signature};
pub use self::transaction::Transaction;
use super::util;
