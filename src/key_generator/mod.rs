//! # Secret key generator

use address::{ADDRESS_BYTES, Address};
use crypto::digest::Digest;
use crypto::sha3::{Sha3, Sha3Mode};
use rand::ThreadRng;
use secp256k1::{Error, Secp256k1};
use secp256k1::key::{PublicKey, SecretKey};

lazy_static! {
    static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

/// Errors for key generation.
pub enum GeneratorError {
    /// Can't generate new key.
    InvalidKey,
}

impl From<Error> for GeneratorError {
    fn from(err: Error) -> Self {
        GeneratorError::InvalidKey
    }
}

/// Secret key generator.
pub struct Generator<'call> {
    rng: &'call Fn() -> ThreadRng,
}

impl<'call> Generator<'call> {
    /// Create a new `Generator`.
    ///
    /// # Arguments
    ///
    /// * `r` - random number generator.
    ///
    fn new(r: &'call Fn() -> ThreadRng) -> Self {
        Generator { rng: r }
    }
}

impl<'call> Iterator for Generator<'call> {
    type Item = SecretKey;

    fn next(&mut self) -> Option<Self::Item> {
        Some(SecretKey::new(&SECP256K1, &mut (self.rng)()))
    }
}

/// Creates a new public key from a secret key.
pub fn to_public(sec: &SecretKey) -> Result<PublicKey, Error> {
    PublicKey::from_secret_key(&SECP256K1, sec)
}

/// Creates a new address from a secret key.
pub fn to_address(sec: &SecretKey) -> Result<Address, Error> {
    let mut res: [u8; 32] = [0; 32];
    let mut sha3 = Sha3::new(Sha3Mode::Keccak256);
    let pk_data = to_public(sec)
        .and_then(|i| Ok(i.serialize_vec(&SECP256K1, false)))
        .unwrap();

    sha3.input(&pk_data);
    sha3.result(&mut res);

    let mut addr_data: [u8; ADDRESS_BYTES] = [0u8; 20];
    addr_data.copy_from_slice(&res[11..32]);

    Ok(Address::new(addr_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn should_generate_keys() {
        let rng = thread_rng;
        let mut gen = Generator::new(&rng);
        let mut keys = Vec::new();

        for _ in 0..5 {
            keys.push(gen.next());
        }

        assert_eq!(keys.len(), 5);
    }

    #[test]
    fn should_convert_to_public() {
        let (sk, pk) = SECP256K1.generate_keypair(&mut thread_rng()).unwrap();
        let extracted = to_public(&sk).unwrap();

        assert_eq!(pk, extracted);
    }

    #[test]
    fn should_convert_to_address() {
        let (sk, pk) = SECP256K1.generate_keypair(&mut thread_rng()).unwrap();

        //        assert_eq!(keys.len(), gen_ticks as usize);
    }
}
