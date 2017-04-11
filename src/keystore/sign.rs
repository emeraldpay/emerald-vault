//!
//! Message signature with Secp256k1
//!

extern crate secp256k1;

use self::secp256k1::{ContextFlag, Message, Secp256k1};
use self::secp256k1::key::SecretKey;
use keystore::KeyFile;

/// Sing errors
pub enum SignError {
    /// Unable to get Private Key using provided passphrase
    UnableToGetPk,

    /// Private Key is corrupted
    CorruptedPk,

    /// Failed to sign
    SignFailure,
}

/// Sign hash with provide private key
pub fn sign(pk: &[u8; 32], hash: &[u8; 32]) -> Result<[u8; 64], SignError> {
    let signer = Secp256k1::with_caps(ContextFlag::SignOnly);
    match SecretKey::from_slice(&signer, pk) {
        Ok(sk) => {
            let msg = Message::from_slice(hash).expect("Expect valid hash");
            match signer.sign_schnorr(&msg, &sk) {
                Ok(sign) => {
                    let mut buf = [0u8; 64];
                    buf.copy_from_slice(sign.serialize().as_slice());
                    Ok(buf)
                }
                Err(_) => Err(SignError::SignFailure),
            }
        }
        Err(_) => Err(SignError::CorruptedPk),
    }
}

impl KeyFile {
    /// Sign message using the key
    pub fn sign(&self, hash: &[u8; 32], passphrase: &str) -> Result<[u8; 64], SignError> {
        match self.extract_key(passphrase) {
            Ok(pk) => sign(&pk, &hash),
            Err(_) => Err(SignError::UnableToGetPk),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::sign;
    use rustc_serialize::hex::FromHex;

    fn as_32bytes(hex: &str) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(hex.from_hex().unwrap().as_slice());
        buf
    }

    #[test]
    fn can_sign() {
        let pk = as_32bytes("dcb2652ce3f3e46a57fd4814f926daefd6082c5cda44d35a6fd0f6da67ca256e");
        let hash = as_32bytes("1f483adb4a0f8c53d0ff8b6df23bbeae846815e7a52bac234edeaeb082b8d51a");
        assert!(sign(&pk, &hash).is_ok());
    }

}
