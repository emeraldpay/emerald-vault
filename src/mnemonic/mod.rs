//! # Module to work with mnemonic codes
//!
//! Refer `BIP39` for detailed specification on mnemonic codes
//! [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

mod error;
mod language;

pub use self::error::Error;
pub use self::language::{Language, BIP39_ENGLISH_WORDLIST};
pub use hdwallet::bip32::{generate_key, HDPath};
use keystore::{Kdf, Prf};
use num::bigint::BigUint;
use num::{FromPrimitive, ToPrimitive};
use rand::{OsRng, Rng};
use sha2::{self, Digest};
use std::iter::repeat;
use std::ops::{BitAnd, Shr};

/// Size of entropy in bytes
pub const ENTROPY_BYTE_LENGTH: usize = 32;
/// Count of iterations for `pbkdf2`
const PBKDF2_ROUNDS: usize = 2048;
/// word index size in bits
const INDEX_BIT_SIZE: usize = 11;
/// Size of mnemonic in words
const MNEMONIC_SIZE: usize = 24;

/// Mnemonic phrase
#[derive(Debug, Clone)]
pub struct Mnemonic {
    language: Language,
    words: Vec<String>,
}

/// Length of mnemonic phrase in words
#[derive(Debug, PartialEq)]
#[allow(dead_code, missing_docs)]
pub enum MnemonicSize {
    Size12 = 12,
    Size15 = 15,
    Size18 = 18,
    Size21 = 21,
    Size24 = 24,
}

impl MnemonicSize {
    /// Number of words
    pub fn values() -> [usize; 5] {
        [12, 15, 18, 21, 24]
    }
}

impl Mnemonic {
    /// Create new mnemonic phrase for selected language
    ///
    /// # Arguments:
    ///
    /// * lang - language for words selection
    ///
    pub fn new(lang: Language, entropy: &[u8]) -> Result<Mnemonic, Error> {
        let mut ent = entropy.to_owned();
        let checksum = checksum(&ent);
        ent.push(checksum);

        let indexes = get_indexes(&ent)?;
        let mut w = Vec::new();
        for i in &indexes {
            w.push(BIP39_ENGLISH_WORDLIST[*i].clone());
        }

        Ok(Mnemonic {
            language: lang,
            words: w,
        })
    }

    /// Convert mnemonic to single string
    pub fn sentence(&self) -> String {
        let mut s = String::new();
        for (i, w) in self.words.iter().enumerate() {
            s.push_str(w);
            if i != self.words.len() - 1 {
                s.push_str(" ");
            }
        }
        s
    }

    /// Get seed from mnemonic sentence
    ///
    /// # Arguments:
    ///
    /// * password - password for seed generation
    ///
    pub fn seed(&self, password: &str) -> Vec<u8> {
        let passphrase = "mnemonic".to_string() + password;
        //        pbkdf2::derive(
        //            &digest::SHA512,
        //            PBKDF2_ROUNDS as u32,
        //            passphrase.as_bytes(),
        //            self.sentence().as_bytes(),
        //            &mut seed,
        //        );
        let prf = Kdf::Pbkdf2 {
            prf: Prf::HmacSha512,
            c: PBKDF2_ROUNDS as u32,
        };

        prf.derive(64, passphrase.as_bytes(), &self.sentence())
    }

    /// Convert a string into `Mnemonic`.
    ///
    /// # Arguments
    ///
    /// * `lang` - A mnemonic language
    /// * `src` - A mnemonic sentence with `MNEMONIC_SIZE` length
    ///
    pub fn try_from(lang: Language, src: &str) -> Result<Self, Error> {
        let w: Vec<String> = src
            .to_string()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        match w.len() {
            0 => Err(Error::MnemonicError("empty initial sentence".to_string())),
            l if MnemonicSize::values().contains(&l) => Ok(Mnemonic {
                language: lang,
                words: w,
            }),
            _ => Err(Error::MnemonicError(
                "invalid initial sentence length".to_string(),
            )),
        }
    }
}

/// Generate entropy

/// # Arguments:
///
/// * `byte_length` - size of entropy in bytes
///
pub fn gen_entropy(byte_length: usize) -> Result<Vec<u8>, Error> {
    let mut rng = OsRng::new()?;
    let entropy = rng.gen_iter::<u8>().take(byte_length).collect::<Vec<u8>>();

    Ok(entropy)
}

/// Calculate checksum for mnemonic
fn checksum(data: &[u8]) -> u8 {
    let mut hash = sha2::Sha256::new();
    hash.input(data);
    hash.result()[0]
}

/// Get indexes from entropy
///
/// # Arguments:
///
/// * `entropy` - slice with entropy
///
fn get_indexes(entropy: &[u8]) -> Result<Vec<usize>, Error> {
    if entropy.len() < ENTROPY_BYTE_LENGTH {
        return Err(Error::MnemonicError(format!(
            "invalid entropy length (required: {}, received: {})",
            ENTROPY_BYTE_LENGTH,
            entropy.len()
        )));
    }

    let mut data = BigUint::from_bytes_be(entropy);
    let index = BigUint::from_u16(0x07ff).expect("expect initialize word index");
    let mut out: Vec<usize> = Vec::with_capacity(MNEMONIC_SIZE);
    for _ in 0..MNEMONIC_SIZE {
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
    out.reverse();

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

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
        let res = get_indexes(&ent);
        assert!(res.is_ok());

        let mut indexes = res.unwrap();
        assert_eq!(indexes.len(), MNEMONIC_SIZE);

        indexes = indexes.into_iter().filter(|v| *v > 2048).collect();
        assert_eq!(indexes.len(), 0);
    }

    #[test]
    fn should_fail_generate_indexes() {
        let res = get_indexes(&vec![0u8, 1u8]);
        assert!(res.is_err())
    }

    #[test]
    fn should_convert_to_seed() {
        let entropy = gen_entropy(ENTROPY_BYTE_LENGTH).unwrap();
        let mnemonic = Mnemonic::new(Language::English, &entropy).unwrap();

        let seed = mnemonic.seed("12345");
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn should_convert_to_sentence() {
        let entropy = gen_entropy(ENTROPY_BYTE_LENGTH).unwrap();
        let mnemonic = Mnemonic::new(Language::English, &entropy).unwrap();
        let s: Vec<String> = mnemonic
            .sentence()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(s, mnemonic.words)
    }

    #[test]
    fn should_generate_english_mnemonic() {
        let entropy = vec![0u8; ENTROPY_BYTE_LENGTH];
        let res = Mnemonic::new(Language::English, &entropy);
        assert!(res.is_ok());

        let mnemonic = res.unwrap();
        assert_eq!(
            mnemonic.sentence(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon art"
        );

        let seed = mnemonic.seed("TREZOR");
        assert_eq!(seed, Vec::from_hex("bda85446c68413707090a52022edd26a\
            1c9462295029f2e60cd7c4f2bbd309717\
            0af7a4d73245cafa9c3cca8d561a7c3de6\
            f5d4a10be8ed2a5e608d68f92fcc8").unwrap());
    }

    #[test]
    fn should_create_from_sentence_12() {
        let s = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic";
        let mnemonic = Mnemonic::try_from(Language::English, s).unwrap();
        let w: Vec<String> = s
            .to_string()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(w, mnemonic.words);
        assert_eq!(mnemonic.seed("TREZOR"), Vec::from_hex("274ddc525802f7c828d8ef7ddbcdc530\
            4e87ac3535913611fbbfa986d0c9e547\
            6c91689f9c8a54fd55bd38606aa6a859\
            5ad213d4c9c9f9aca3fb217069a41028").unwrap());
    }

    #[test]
    fn should_create_from_sentence_24() {
        let s = "beyond stage sleep clip because twist token leaf atom beauty genius food \
                 business side grid unable middle armed observe pair crouch tonight away coconut";
        let mnemonic = Mnemonic::try_from(Language::English, s).unwrap();
        let w: Vec<String> = s
            .to_string()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(w, mnemonic.words);
        assert_eq!(mnemonic.seed("TREZOR"), Vec::from_hex("b15509eaa2d09d3efd3e006ef42151b3\
            0367dc6e3aa5e44caba3fe4d3e352e65\
            101fbdb86a96776b91946ff06f8eac59\
            4dc6ee1d3e82a42dfe1b40fef6bcc3fd").unwrap());
    }

    #[test]
    fn should_fail_from_empty() {
        let s = "";
        let mnemonic = Mnemonic::try_from(Language::English, s);

        assert!(mnemonic.is_err())
    }

    #[test]
    fn should_fail_from_longer() {
        let s = "test test test test test test test test test test test test test test test test \
                 test test test test test test test test test test test test test";
        let mnemonic = Mnemonic::try_from(Language::English, s);

        assert!(mnemonic.is_err())
    }

    #[test]
    fn should_fail_from_outrange() {
        let s = "test test test test test test test test test test test test test test test test";
        let mnemonic = Mnemonic::try_from(Language::English, s);

        assert!(mnemonic.is_err())
    }
}
