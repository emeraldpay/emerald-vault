use crate::{KECCAK256_BYTES, Signature};
use crate::crypto::error::CryptoError;

trait AsHash {
    fn as_hash(&self) -> [u8; KECCAK256_BYTES];
}

trait Signer {
    fn sign<T: AsHash>(&self, msg: T) -> Result<Signature, CryptoError>;
}
