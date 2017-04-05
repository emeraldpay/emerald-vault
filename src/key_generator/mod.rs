extern crate secp256k1;
extern crate rand;

use self::secp256k1::{Secp256k1};
use self::secp256k1::key::{SecretKey};
use self::rand::{thread_rng, ThreadRng};


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
    secp256: Secp256k1,
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
    fn new(t: u64, r: &'call Fn() -> ThreadRng) -> Self{
        Generator {
            ticks: t,
            secp256: Secp256k1::new(),
            thread_rng: r
        }
    }
}

impl<'call> Iterator for Generator<'call> {
    type Item = SecretKey;

    fn next(&mut self) -> Option<Self::Item> {
        if  self.ticks > 0 {
            self.ticks -= 1;
            Some(SecretKey::new(&self.secp256, &mut (self.thread_rng)()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use self::rand::thread_rng;

    #[test]
    fn should_generate_keys() {
        let gen_ticks = 100;
        let rng = thread_rng;
        let gen = Generator::new(gen_ticks, &rng);

        let keys = gen.collect::<Vec<_>>();
        assert_eq!(keys.len(), gen_ticks as usize);
    }
}