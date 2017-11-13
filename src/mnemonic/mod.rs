//! # Module to work with mnemonic codes
//!
//! Refer `BIP39` for detailed specification on mnemonic codes
//! [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

mod error;
mod language;

use self::error::Error;
use self::language::{BIP39_ENGLISH_WORDLIST, Language};
use crypto::digest::Digest;
use crypto::sha2;
use keystore::{Kdf, Prf};
use num::{FromPrimitive, ToPrimitive};
use num::bigint::BigUint;
use rand::{OsRng, Rng};
use std::iter::repeat;
use std::ops::{BitAnd, Shr};


/// Size of entropy in bytes
const ENTROPY_BYTE_LENGTH: usize = 32;
/// Count of iterations for `pbkdf2`
const PBKDF2_ROUNDS: usize = 2048;
/// word index size in bits
const INDEX_BIT_SIZE: usize = 11;


/// Mnemonic phrase
#[derive(Debug, Clone)]
pub struct Mnemonic {
    entropy: Vec<u8>,
    language: Language,
    words: Vec<String>,
}


impl Mnemonic {
    /// Create new mnemonic phrase for selected language
    ///
    /// # Arguments:
    ///
    /// * lang - language for words selection
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
            entropy: entropy,
            language: lang,
            words: words,
        })
    }

    /// Convert mnemonic to single string
    pub fn sentence(&self) -> String {
        let mut s = String::new();
        for w in &self.words {
            s.push_str(" ");
            s.push_str(w);
        }
        s
    }

    /// Get seed from mnemonic sentence
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

/// Calculate checksum for mnemonic
fn checksum(data: &[u8]) -> u8 {
    let mut hash = sha2::Sha256::new();
    hash.input(data);

    let mut out: Vec<u8> = repeat(0).take(32).collect();
    hash.result(&mut out);

    out[0]
}

/// Generate entropy
fn gen_entropy(byte_length: usize) -> Result<Vec<u8>, Error> {
    let mut rng = OsRng::new()?;
    let entropy = rng.gen_iter::<u8>().take(byte_length).collect::<Vec<u8>>();

    Ok(entropy)
}

/// Get indexes from entropy
fn get_indexes(entropy: &[u8]) -> Result<Vec<usize>, Error> {
    let mut data = BigUint::from_bytes_be(entropy);
    let index = BigUint::from_u16(0x07ff).expect("expect initialize word index");
    let mut out: Vec<usize> = Vec::with_capacity(24);
    for _ in 0..24 {
        match data.clone().bitand(index.clone()).to_usize() {
            Some(v) => out.push(v),
            None => {
                return Err(Error::MnemonicError(
                    "can't extract words indexes".to_string(),
                ))
            }
        }
        data = data.shr(INDEX_BIT_SIZE);
    }
    Ok(out)
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn should_generate_entropy() {
        let mut ent = gen_entropy(ENTROPY_BYTE_LENGTH);
        assert!(ent.is_ok());
        assert_eq!(ent.unwrap().len(), ENTROPY_BYTE_LENGTH);

        ent = gen_entropy(2);
        assert!(ent.is_ok());
        assert_eq!(ent.unwrap().len(), 2);
    }

    #[test]
    fn should_generate_indexes() {
        let ent = gen_entropy(ENTROPY_BYTE_LENGTH).unwrap();
        let mut indexes = get_indexes(&ent);
        assert!(indexes.is_ok());

        let mut i = indexes.unwrap();
        assert_eq!(i.len(), 24);

        i = i.into_iter().filter(|v| *v > 2048).collect();
        assert_eq!(i.len(), 0);
    }

    #[test]
    fn should_generate_mnemonic() {
        let mnemonic = Mnemonic::new(Language::English);
        assert!(mnemonic.is_ok());

        let m = mnemonic.unwrap();
        assert_eq!(m.words.len(), 24);
    }

    #[test]
    fn should_convert_to_seed() {
        let mnemonic = Mnemonic::new(Language::English).unwrap();

        let seed = mnemonic.seed("12345");
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn should_convert_to_sentence() {
        let mnemonic = Mnemonic::new(Language::English).unwrap();
        let s: Vec<String> = mnemonic
            .sentence()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(s, mnemonic.words)
    }
}
