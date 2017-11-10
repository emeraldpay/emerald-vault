//! # Module to work with mnemonic codes
//!
//! Refer `BIP39` for detailed specification on mnemonic codes
//! [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

mod error;
mod language;

use self::error::Error;
use self::language::{Language, BIP39_ENGLISH_WORDLIST};
use crypto::sha2;
use keystore::{Kdf, Prf};
use num::bigint::BigUint;
use num::{FromPrimitive, ToPrimitive};
use rand::{OsRng, Rng};
use std::ops::{BitAnd, Shr};
use crypto::digest::Digest;
use std::iter::repeat;


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


/// Mnemonic phrase
impl Mnemonic {

    /// Create new mnemonic phrase for selected language
    ///
    ///
    pub fn new(lang: Language) -> Result<Mnemonic, Error> {
        let mut entropy = gen_entropy(ENTROPY_BYTE_LENGTH)?;
        let checksum = checksum(&entropy);
        entropy.push(checksum);

        let indexes = get_indexes(&entropy)?;
        let mut words = Vec::new();
        for i in indexes.iter() {
            words.push(BIP39_ENGLISH_WORDLIST[*i].clone());
        }

        Ok(Mnemonic {
            size: size,
            entropy: entropy,
            language: lang,
            words: words,
        })
    }

    pub fn sentence(&self) -> String {
        let mut s = String::new();
        for w in &self.words {
            s.push_str(w)
        };
        s
    }

    pub fn seed(&self, password: &str) -> Vec<u8> {
        let kdf = Kdf::Pbkdf2 {
            prf: Prf::HmacSha512,
            c: PBKDF2_ROUNDS as u32,
        };
        let passphrase = "mnemonic".to_string() + password;
        let salt: Vec<u8> = passphrase.bytes().collect();

        kdf.derive(64, &salt, &self.sentence())
    }
}

fn checksum(data: &[u8]) -> u8 {
    let mut hash = sha2::Sha256::new();
    hash.input(data);

    let mut out: Vec<u8> = repeat(0).take(32).collect();
    hash.result(&mut out);

    out[0]
}

fn gen_entropy(byte_length: usize) -> Result<Vec<u8>, Error> {
    let mut rng = OsRng::new()?;
    let entropy = rng.gen_iter::<u8>().take(byte_length).collect::<Vec<u8>>();

    Ok(entropy)
}

fn get_indexes(entropy: &[u8]) -> Result<Vec<usize>, Error> {
    let mut data = BigUint::from_bytes_be(entropy);
    let index = BigUint::from_u16(0x07ff).expect("expect initialize word index");
    let mut out: Vec<usize> = Vec::with_capacity(24);
    for _ in 0..24 {
        match data.clone().bitand(index.clone()).to_usize() {
            Some(v) => out.push(v),
            None => return Err(Error::MnemonicError("can't extract words indexes".to_string())),
        }
        data = data.shr(INDEX_BIT_SIZE);
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn should_generate_mnemonic() {
        let  res = Mnemonic::new(Language::English);
        assert!(res.is_ok());

        let m = res.unwrap();
        assert_eq!(m.words.len(), 24);
    }

    #[test]
    fn should_convert_to_seed() {
        let  res = Mnemonic::new(Language::English);
        assert!(res.is_ok());

        let m = res.unwrap();
        assert_eq!(m.words.len(), 24);
    }

}