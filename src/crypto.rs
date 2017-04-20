//! Sign messages

use super::PrivateKey;
use crypto::digest::Digest;
use crypto::sha3::{Sha3, Sha3Mode};
use secp256k1::{ContextFlag, Error, Message, Secp256k1};
use secp256k1::key::SecretKey;

/// Keccak-256 hash length in bytes
pub const KECCAK256_BYTES: usize = 32;

/// Calculate hash for data (KECCAK-256) and sign it with provide private key
pub fn sign_data(data: &[u8], pk: &PrivateKey) -> Result<[u8; 64], Error> {
    sign_hash(keccak256(data), pk)
}

/// Sign hashed message (KECCAK-256) with provide private key
pub fn sign_hash(hash: &[u8; KECCAK256_BYTES], pk: &PrivateKey) -> Result<[u8; 64], Error> {
    let signer = Secp256k1::with_caps(ContextFlag::SignOnly);
    let sk = (SecretKey::from_slice(&signer, pk))?;

    let msg = Message::from_slice(hash).expect("Expect valid hash message");
    let sign = (signer.sign_schnorr(&msg, &sk))?;

    let mut buf = [0u8; 64];
    buf.copy_from_slice(sign.serialize().as_slice());
    Ok(buf)
}

/// KECCAK-256 crypto hash
pub fn keccak256(data: &[u8]) -> [u8; KECCAK256_BYTES] {
    let mut sha3 = Sha3::new(Sha3Mode::Keccak256);
    sha3.input(data);

    let mut hash = [0u8; 32];
    sha3.result(&mut hash);
    hash
}

#[cfg(test)]
mod tests {
    use super::sign_hash;
    use rustc_serialize::hex::FromHex;

    fn as_32bytes(hex: &str) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&hex.from_hex().unwrap());
        buf
    }

    #[test]
    fn should_sign_hash() {
        let hash = as_32bytes("1f483adb4a0f8c53d0ff8b6df23bbeae846815e7a52bac234edeaeb082b8d51a");
        let pk = as_32bytes("dcb2652ce3f3e46a57fd4814f926daefd6082c5cda44d35a6fd0f6da67ca256e");

        assert!(sign_hash(&hash, &pk).is_ok());
    }
}
