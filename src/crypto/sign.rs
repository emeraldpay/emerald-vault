use crate::crypto::error::CryptoError;
use crate::{Signature, KECCAK256_BYTES};

trait AsHash {
    fn as_hash(&self) -> [u8; KECCAK256_BYTES];
}

trait Signer {
    fn sign<T: AsHash>(&self, msg: T) -> Result<Signature, CryptoError>;
}
