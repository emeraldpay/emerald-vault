use crate::convert::proto::pk::PrivateKeyHolder;
use crate::{KECCAK256_BYTES, Signature, ECDSA_SIGNATURE_BYTES};
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::{Message, Secp256k1, SignOnly};
use crate::crypto::error::CryptoError;

trait AsHash {
    fn as_hash(&self) -> [u8; KECCAK256_BYTES];
}

trait Signer {
    fn sign<T: AsHash>(&self, msg: T) -> Result<Signature, CryptoError>;
}
