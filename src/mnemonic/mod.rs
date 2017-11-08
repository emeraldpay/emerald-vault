//! # Module to work with mnemonic codes
//!
//! Refer `BIP39` for detailed specification on mnemonic codes
//! [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

mod error;
mod language;

use self::error::Error;
use self::language::Language;
use crypto::sha2;
use keystore::{Kdf, Prf};
use num::bigint::BigUint;
use num::{FromPrimitive, ToPrimitive};
use rand::{OsRng, Rng};
use std::ops::{BitAnd, Shl};
use crypto::digest::Digest;


/// Size of entropy in bytes
const ENTROPY_BYTE_LENGTH: usize = 32;
/// Count of iterations for `pbkdf2`
const PBKDF2_ROUNDS: usize = 2048;
/// word index size in bits
const INDEX_BIT_SIZE: usize = 11;

#[derive(Debug, Copy, Clone)]
pub enum MnemonicSize {
    Size12 = 12,
    Size15 = 15,
    Size18 = 18,
    Size21 = 21,
    Size24 = 24,
}

#[derive(Debug, Clone)]
pub struct Mnemonic {
    size: MnemonicSize,
    entropy: Vec<u8>,
    language: Language,
    words: Vec<String>
}

pub struct Seed {
    value: [u8; 64],
}


impl Mnemonic {
    pub fn new(size: MnemonicSize, lang: Language) -> Result<Mnemonic, Error> {
        let mut entropy = gen_entropy(ENTROPY_BYTE_LENGTH)?;
        let checksum = checksum(&entropy);
        entropy.push(checksum);

        Ok(Mnemonic {
            size: size,
            entropy: entropy,
            language: lang,
            words: Vec::new(),
        })
    }

    pub fn sentence(&self) -> String {
        let mut s = String::new();
        for w in self.words.iter() {
            s.push_str(&w)
        };
        s
    }

    fn seed(&self, password: String) -> Vec<u8> {
        let kdf = Kdf::Pbkdf2 {
            prf: Prf::HmacSha512,
            c: PBKDF2_ROUNDS as u32,
        };
        let passphrase = "mnemonic".to_string() + &password;
        let salt: Vec<u8> = passphrase.bytes().collect();

        kdf.derive(64, &salt, &self.sentence())
    }
}

fn checksum(data: &[u8]) -> u8 {
    let mut hash = sha2::Sha256::new();
    hash.input(data);

    let mut out = Vec::new();
    hash.result(out.as_mut_slice());

    out[0]
}

fn gen_entropy(byte_length: usize) -> Result<Vec<u8>, Error> {
    let mut rng = OsRng::new()?;
    let entropy = rng.gen_iter::<u8>().take(byte_length).collect::<Vec<u8>>();

    Ok(entropy)
}

fn get_indexes(entropy: &[u8; 32]) -> Result<Vec<u16>, Error> {
    let data = BigUint::from_bytes_be(entropy);
    let mut index = BigUint::from_u16(0x07ff).expect("expect initialize word index");
    let mut out: Vec<u16> = vec!();

    for _ in 0..24 {
        match data.clone().bitand(index.clone()).to_u16() {
            Some(v) => out.push(v),
            None => return Err(Error::MnemonicError("can't extract words indexes".to_string())),
        }
        index = index.shl(INDEX_BIT_SIZE);
    };

    Ok(out)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_generate_mnemonic() {

    }

}