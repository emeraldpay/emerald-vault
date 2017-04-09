extern crate secp256k1;
extern crate rand;
extern crate tiny_keccak;

use self::rand::{ThreadRng, thread_rng};
use self::secp256k1::{Error, Secp256k1};
use self::secp256k1::key::{PublicKey, SecretKey};
use self::tiny_keccak::Keccak;
use address::{ADDRESS_BYTES, Address};

lazy_static! {
    static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

/// Errors for key generation.
pub enum GeneratorError {
    InvalidKey,
}

impl From<secp256k1::Error> for GeneratorError {
    fn from(err: secp256k1::Error) -> Self {
        GeneratorError::InvalidKey
    }
}

/// Secret key generator.
/// Runs for `ticks` times, yielding each time key.
pub struct Generator<'call> {
    ticks: u64,
    thread_rng: &'call Fn() -> ThreadRng,
}

impl<'call> Generator<'call> {
    /// Create a new `Generator`.
    ///
    /// # Arguments
    ///
    /// * `ticks` - number of yielded keys.
    /// * `r` - random number generator.
    ///
    /// # Example
    ///
    /// ```
    /// let gen = Generator::new(100, &rng);
    /// assert_eq!(gen.collect::<Vec<_>>().len(), 100);
    /// ```
    fn new(t: u64, r: &'call Fn() -> ThreadRng) -> Self {
        Generator {
            ticks: t,
            thread_rng: r,
        }
    }
}

impl<'call> Iterator for Generator<'call> {
    type Item = SecretKey;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ticks > 0 {
            self.ticks -= 1;
            Some(SecretKey::new(&SECP256K1, &mut (self.thread_rng)()))
        } else {
            None
        }
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
    use self::rand::thread_rng;
    use super::*;

    #[test]
    fn should_generate_keys() {
        let gen_ticks = 100;
        let rng = thread_rng;
        let gen = Generator::new(gen_ticks, &rng);

        let keys = gen.collect::<Vec<_>>();
        assert_eq!(keys.len(), gen_ticks as usize);
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
