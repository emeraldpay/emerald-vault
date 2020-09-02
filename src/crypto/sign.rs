use crate::crypto::error::CryptoError;
use crate::{EthereumSignature, KECCAK256_BYTES};

trait AsHash {
    fn as_hash(&self) -> [u8; KECCAK256_BYTES];
}

trait Signer {
    fn sign<T: AsHash>(&self, msg: T) -> Result<EthereumSignature, CryptoError>;
}
