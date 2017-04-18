///! # Private key used in ECDSA signatures on the secp256k1 curve

use address::{ADDRESS_BYTES, Address};
use crypto::digest::Digest;
use crypto::sha3::{Sha3, Sha3Mode};
use key_generator::{Generator, SECP256K1};
use secp256k1::{Error as SecpError, Secp256k1};
use secp256k1::key::{PublicKey, SecretKey};
use std::slice;

/// Private key length in bytes
pub const PRIVATE_KEY_BYTES: usize = 32;

/// Private key object for use in `KeyFile`
pub struct PrivateKey {
    skey: SecretKey,
}

impl PrivateKey {
    /// Create new `PrivateKey` using secp256k1 secret key
    pub fn new(sk: SecretKey) -> Self {
        PrivateKey { skey: sk }
    }

    /// Create new `PrivateKey` from an array slice
    pub fn from_slice(data: &[u8]) -> Self {
        let sk = SecretKey::from_slice(&SECP256K1, data);
        PrivateKey::new(sk.expect("Expect to receive secret key"))
    }

    /// Creates a new public key from a secret key.
    pub fn to_public(&self) -> Result<PublicKey, SecpError> {
        PublicKey::from_secret_key(&SECP256K1, &self.skey)
    }

    /// Creates a new address from a secret key.
    pub fn to_address(&self) -> Result<Address, SecpError> {
        let mut res: [u8; 32] = [0; 32];
        let mut sha3 = Sha3::new(Sha3Mode::Keccak256);
        let pk_data = self.to_public()
            .and_then(|i| Ok(i.serialize_vec(&SECP256K1, false)))
            .unwrap();

        sha3.input(&pk_data);
        sha3.result(&mut res);

        let mut addr_data: [u8; ADDRESS_BYTES] = [0u8; 20];
        addr_data.copy_from_slice(&res[12..]);

        Ok(Address::new(addr_data))
    }
}

impl Into<[u8; 32]> for PrivateKey {
    fn into(mut self) -> [u8; 32] {
        unsafe {
            let mut val = [0u8; 32];
            val.clone_from_slice(slice::from_raw_parts(self.skey.as_ptr(), PRIVATE_KEY_BYTES));
            val
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn should_convert_to_public() {}

    #[test]
    fn should_convert_to_address() {}
}
