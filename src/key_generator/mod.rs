//! # Secret key generator

use address::{ADDRESS_BYTES, Address};
use rand::{ThreadRng, thread_rng};
use secp256k1::{Error, Secp256k1};
use secp256k1::key::{PublicKey, SecretKey};
use tiny_keccak::Keccak;

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
    /// # Example
    ///
    /// ```
    /// let gen = Generator::new(100, &rng);
    /// assert_eq!(gen.collect::<Vec<_>>().len(), 100);
    /// ```
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
    let mut sha3 = Keccak::new_sha3_256();
    let pk_data = to_public(sec)
        .and_then(|i| Ok(i.serialize_vec(&SECP256K1, false)))
        .unwrap();

    let mut res: [u8; 32] = [0; 32];
    sha3.update(&pk_data);
    sha3.finalize(&mut res);

    let mut addr_data: [u8; ADDRESS_BYTES] = [0u8; 20];
    addr_data.copy_from_slice(&res[11..32]);

    Ok(Address::new(addr_data))
}

#[cfg(test)]
mod tests {
    use super::*;

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
