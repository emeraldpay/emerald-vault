//! # Secret key generator

pub mod util;

use rand::OsRng;
use secp256k1::{Error as SecpError, Secp256k1};
use secp256k1::key::{PublicKey, SecretKey};


lazy_static! {
    static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

/// Errors for key generation
pub enum GeneratorError {
    /// Can't generate new key
    InvalidKey,
}

impl From<SecpError> for GeneratorError {
    fn from(err: SecpError) -> Self {
        GeneratorError::InvalidKey
    }
}

/// Secret key generator
pub struct Generator {
    rng: OsRng,
}

impl Generator {
    /// Create a new `Generator`
    ///
    /// # Arguments
    ///
    /// * `r` - random number generator
    ///
    fn new(r: OsRng) -> Self {
        Generator { rng: r }
    }

    /// Generate new `SecretKey`
    fn get(&mut self) -> SecretKey {
        SecretKey::new(&SECP256K1, &mut self.rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::OsRng;

    #[test]
    fn should_generate_keys() {
        let rng = OsRng::new().unwrap();
        let mut gen = Generator::new(rng);
        let mut keys = Vec::new();

        for _ in 0..5 {
            keys.push(gen.get());
        }

        assert_eq!(keys.len(), 5);
    }
}
