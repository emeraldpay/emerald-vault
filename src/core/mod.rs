//! # Core domain logic module

mod address;
mod error;
mod signature;
mod transaction;

pub use self::address::Address;
pub use self::error::Error;
pub use self::signature::{ECDSA_SIGNATURE_BYTES, PRIVATE_KEY_BYTES, PrivateKey};
pub use self::transaction::{Signature, Transaction};
use super::util;
