/*
Copyright 2019 ETCDEV GmbH
Copyright 2020 EmeraldPay, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//! # Module to work with mnemonic codes
//!
//! Refer `BIP39` for detailed specification on mnemonic codes
//! [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

mod error;
mod language;

pub use self::{
    error::Error,
    language::{Language, BIP39_ENGLISH_WORDLIST},
};
pub use crate::hdwallet::bip32::generate_key;
use hmac::Hmac;
use num::{bigint::BigUint, FromPrimitive, ToPrimitive};
use pbkdf2::pbkdf2;
use rand::{distributions::Standard, rngs::OsRng, Rng};
use sha2::{Digest, Sha512};
use std::ops::{BitAnd, Shr};

/// Count of iterations for `pbkdf2`
const PBKDF2_ROUNDS: u32 = 2048;
/// word index size in bits
const INDEX_BIT_SIZE: u32 = 11;

/// Mnemonic phrase
#[derive(Debug, Clone)]
pub struct Mnemonic {
    language: Language,
    words: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub struct MnemonicSize {
    bits_length: usize,
    checksum_length: usize,
}

/// Standard Mnemonics
pub struct StandardMnemonic {}

impl StandardMnemonic {
    /// Most secure mnemonic (24 words currently)
    pub fn secure() -> MnemonicSize {
        StandardMnemonic::size24()
    }
    /// Simple mnemonic suitable for a single address generation (15 words)
    pub fn simple() -> MnemonicSize {
        StandardMnemonic::size15()
    }

    /// 12 words mnemonic
    pub fn size12() -> MnemonicSize {
        MnemonicSize::from_length(12).unwrap()
    }
    /// 15 words mnemonic
    pub fn size15() -> MnemonicSize {
        MnemonicSize::from_length(15).unwrap()
    }
    /// 18 words mnemonic
    pub fn size18() -> MnemonicSize {
        MnemonicSize::from_length(18).unwrap()
    }
    /// 21 words mnemonic
    pub fn size21() -> MnemonicSize {
        MnemonicSize::from_length(21).unwrap()
    }
    /// 24 words mnemonic
    pub fn size24() -> MnemonicSize {
        MnemonicSize::from_length(24).unwrap()
    }
}

impl MnemonicSize {
    pub fn standard() -> [MnemonicSize; 5] {
        [
            MnemonicSize::from_length(12).unwrap(),
            MnemonicSize::from_length(15).unwrap(),
            MnemonicSize::from_length(18).unwrap(),
            MnemonicSize::from_length(21).unwrap(),
            MnemonicSize::from_length(24).unwrap(),
        ]
    }

    pub fn from_length(words: usize) -> Result<MnemonicSize, Error> {
        match words {
            12 => Ok(MnemonicSize {
                bits_length: 128,
                checksum_length: 4,
            }),
            15 => Ok(MnemonicSize {
                bits_length: 160,
                checksum_length: 5,
            }),
            18 => Ok(MnemonicSize {
                bits_length: 192,
                checksum_length: 6,
            }),
            21 => Ok(MnemonicSize {
                bits_length: 224,
                checksum_length: 7,
            }),
            24 => Ok(MnemonicSize {
                bits_length: 256,
                checksum_length: 8,
            }),
            _ => Err(Error::MnemonicError(format!(
                "Invalid mnemonic size: {}",
                words
            ))),
        }
    }

    pub fn from_entropy(entropy: &[u8]) -> Result<MnemonicSize, Error> {
        let all = MnemonicSize::standard();
        let entropy_len = entropy.len();
        let found = all.iter().find(|x| x.entropy_bytes_length() == entropy_len);
        match found {
            Some(&m) => Ok(m),
            None => Err(Error::MnemonicError(format!(
                "Invalid entropy size: {}",
                entropy_len
            ))),
        }
    }

    pub fn words_count(&self) -> usize {
        (self.bits_length + self.checksum_length) / 11
    }

    pub fn entropy_bytes_length(&self) -> usize {
        self.bits_length / 8
    }

    pub fn full_bytes_length(&self) -> usize {
        let mut rem = 8 - (self.bits_length + self.checksum_length) % 8;
        if rem == 8 {
            rem = 0
        }
        (self.bits_length + self.checksum_length + rem) / 8
    }

    /// Generate a random entropy within current mnemonic size
    pub fn entropy(&self) -> Result<Vec<u8>, Error> {
        gen_entropy(self.entropy_bytes_length())
    }

    pub fn checksum_bits(&self, full: u8) -> u8 {
        if self.checksum_length == 8 {
            full
        } else {
            let mut mask: u8 = 0;
            for _i in 0..self.checksum_length {
                mask |= 1;
                mask = mask << 1;
            }
            mask = mask << (8 - self.checksum_length - 1) as u8;
            let bits = full & mask;
            bits >> (8 - self.checksum_length) as u8
        }
    }
}

impl Default for Mnemonic {
    fn default() -> Self {
        Mnemonic::new(Language::English, StandardMnemonic::secure()).unwrap()
    }
}

impl Mnemonic {
    // Create new mnemonic phrase for selected lanaguage with provided size
    //
    pub fn new(lang: Language, size: MnemonicSize) -> Result<Mnemonic, Error> {
        Mnemonic::from_entropy(lang, size.entropy()?.as_slice())
    }

    /// Create new mnemonic phrase for selected language with provided entropy
    ///
    /// # Arguments:
    ///
    /// * lang - language for words selection
    ///
    pub fn from_entropy(lang: Language, entropy: &[u8]) -> Result<Mnemonic, Error> {
        let size = MnemonicSize::from_entropy(entropy)?;
        let mut ent = entropy.to_owned();
        let checksum = checksum(&ent, size);
        ent = with_checksum(&ent, checksum, size);

        let indexes = get_indexes(&ent, size)?;
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
    pub fn seed(&self, password: Option<&str>) -> Vec<u8> {
        let passphrase = match password {
            Some(p) => "mnemonic".to_string() + &p.to_string(),
            None => "mnemonic".to_string(),
        };

        let mut result = vec![0u8; 64];
        pbkdf2::<Hmac<Sha512>>(
            // password
            &self.sentence().as_str().as_bytes(),
            // salt
            passphrase.as_bytes(),
            // size
            PBKDF2_ROUNDS,
            // result
            &mut result,
        );

        result
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
            l => {
                MnemonicSize::from_length(l)?;
                Ok(Mnemonic {
                    language: lang,
                    words: w,
                })
            }
        }
    }
}

/// Generate entropy

/// # Arguments:
///
/// * `byte_length` - size of entropy in bytes
///
pub fn gen_entropy(byte_length: usize) -> Result<Vec<u8>, Error> {
    // let rng = StdRng::from_entropy();
    let mut rng = OsRng::new()?;
    let bytes = rng.sample_iter(&Standard).take(byte_length).collect();

    Ok(bytes)
}

/// Calculate checksum for mnemonic
fn checksum(data: &[u8], size: MnemonicSize) -> u8 {
    let mut hash = sha2::Sha256::new();
    hash.update(data);
    let val = hash.finalize()[0];
    size.checksum_bits(val)
}

fn with_checksum(entropy: &[u8], checksum: u8, size: MnemonicSize) -> Vec<u8> {
    let mut copy = Vec::from(entropy);
    if size.checksum_length == 8 {
        copy.push(checksum);
        copy
    } else {
        let empty_bits = (8 - size.checksum_length) as u8;
        let checksum_corrected = checksum << empty_bits;
        copy.push(checksum_corrected);

        let full_size = size.full_bytes_length();
        let mut data = BigUint::from_bytes_be(copy.as_slice());
        data = data.clone().shr(empty_bits as usize);
        let result = data.to_bytes_be().to_vec();
        if result.len() < full_size {
            let mut with_zeroes: Vec<u8> = vec![0; full_size - result.len()];
            with_zeroes.extend_from_slice(result.as_slice());
            with_zeroes
        } else {
            result
        }
    }
}

/// Get indexes from entropy
///
/// # Arguments:
///
/// * `entropy` - slice with entropy
///
fn get_indexes(entropy: &[u8], size: MnemonicSize) -> Result<Vec<usize>, Error> {
    if entropy.len() != size.full_bytes_length() {
        return Err(Error::MnemonicError(format!(
            "invalid entropy length (required: {}, received: {})",
            size.full_bytes_length(),
            entropy.len()
        )));
    }

    let data = BigUint::from_bytes_be(entropy);
    // 11 bit for each word
    let base_mask = BigUint::from_u16(0b11111111111).expect("expect initialize word index");
    let mut out: Vec<usize> = Vec::with_capacity(size.words_count());
    for i in 0..size.words_count() {
        let pos = (size.words_count() - 1 - i) * (INDEX_BIT_SIZE as usize);
        match data.clone().shr(pos).bitand(&base_mask.clone()).to_usize() {
            Some(v) => out.push(v),
            None => {
                return Err(Error::MnemonicError(
                    "can't extract words indexes".to_string(),
                ))
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn keeps_zeroes_with_checksum() {
        let zeroes = vec![0; 2]; //0x0000
        let act = with_checksum(zeroes.as_slice(), 15, StandardMnemonic::size12());
        assert_eq!(hex::encode(act), "000000000000000000000000000000000f");

        let zeroes =
            Vec::from_hex("00000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let act = with_checksum(zeroes.as_slice(), 15, StandardMnemonic::size24());
        assert_eq!(
            hex::encode(act),
            "000000000000000000000000000000000000000000000000000000000000000f"
        );

        let zeroes = Vec::from_hex("000100").unwrap();
        let act = with_checksum(zeroes.as_slice(), 15, StandardMnemonic::size12());
        assert_eq!(hex::encode(act), "000000000000000000000000000000100f");

        let zeroes = Vec::from_hex("000000000000000000000000000000000000000000000000").unwrap();
        let act = with_checksum(zeroes.as_slice(), 0b100111, StandardMnemonic::size18());
        assert_eq!(
            hex::encode(act),
            "00000000000000000000000000000000000000000000000027"
        );
    }

    #[test]
    fn should_extract_length() {
        assert_eq!(
            MnemonicSize::from_length(12).unwrap(),
            StandardMnemonic::size12()
        );
        assert_eq!(
            MnemonicSize::from_length(15).unwrap(),
            StandardMnemonic::size15()
        );
        assert_eq!(
            MnemonicSize::from_length(18).unwrap(),
            StandardMnemonic::size18()
        );
        assert_eq!(
            MnemonicSize::from_length(21).unwrap(),
            StandardMnemonic::size21()
        );
        assert_eq!(
            MnemonicSize::from_length(24).unwrap(),
            StandardMnemonic::size24()
        );
    }

    #[test]
    fn should_fail_on_invalid_length() {
        assert!(MnemonicSize::from_length(0).is_err());
        assert!(MnemonicSize::from_length(1).is_err());
        assert!(MnemonicSize::from_length(11).is_err());
        assert!(MnemonicSize::from_length(32).is_err());
    }

    #[test]
    fn should_calc_entropy_length() {
        assert_eq!(StandardMnemonic::size12().entropy_bytes_length(), 16);
        assert_eq!(StandardMnemonic::size15().entropy_bytes_length(), 20);
        assert_eq!(StandardMnemonic::size18().entropy_bytes_length(), 24);
        assert_eq!(StandardMnemonic::size21().entropy_bytes_length(), 28);
        assert_eq!(StandardMnemonic::size24().entropy_bytes_length(), 32);
    }

    #[test]
    fn should_calc_full_length() {
        assert_eq!(StandardMnemonic::size12().full_bytes_length(), 17);
        assert_eq!(StandardMnemonic::size15().full_bytes_length(), 21);
        assert_eq!(StandardMnemonic::size18().full_bytes_length(), 25);
        assert_eq!(StandardMnemonic::size21().full_bytes_length(), 29);
        assert_eq!(StandardMnemonic::size24().full_bytes_length(), 33);
    }

    #[test]
    fn generates_correct_entropy_length() {
        assert_eq!(StandardMnemonic::size12().entropy().unwrap().len(), 16);
        assert_eq!(StandardMnemonic::size15().entropy().unwrap().len(), 20);
        assert_eq!(StandardMnemonic::size18().entropy().unwrap().len(), 24);
        assert_eq!(StandardMnemonic::size21().entropy().unwrap().len(), 28);
        assert_eq!(StandardMnemonic::size24().entropy().unwrap().len(), 32);
    }

    #[test]
    fn generates_correct_mnemonic_length() {
        assert_eq!(
            Mnemonic::new(Language::English, StandardMnemonic::size12())
                .unwrap()
                .words
                .len(),
            12
        );
        assert_eq!(
            Mnemonic::new(Language::English, StandardMnemonic::size15())
                .unwrap()
                .words
                .len(),
            15
        );
        assert_eq!(
            Mnemonic::new(Language::English, StandardMnemonic::size18())
                .unwrap()
                .words
                .len(),
            18
        );
        assert_eq!(
            Mnemonic::new(Language::English, StandardMnemonic::size21())
                .unwrap()
                .words
                .len(),
            21
        );
        assert_eq!(
            Mnemonic::new(Language::English, StandardMnemonic::size24())
                .unwrap()
                .words
                .len(),
            24
        );
    }

    #[test]
    fn should_generate_entropy() {
        let mut ent = gen_entropy(32);
        assert!(ent.is_ok());
        assert_eq!(ent.unwrap().len(), 32);

        ent = gen_entropy(2);
        assert!(ent.is_ok());
        assert_eq!(ent.unwrap().len(), 2);
    }

    #[test]
    fn should_generate_indexes_12words() {
        let mut ent = gen_entropy(16).unwrap();
        ent = with_checksum(ent.as_slice(), 1, StandardMnemonic::size12());
        let res = get_indexes(&ent, StandardMnemonic::size12());
        assert!(res.is_ok());

        let mut indexes = res.unwrap();
        assert_eq!(indexes.len(), 12);

        indexes = indexes.into_iter().filter(|v| *v > 2048).collect();
        assert_eq!(indexes.len(), 0);
    }

    #[test]
    fn should_generate_indexes_15words() {
        let mut ent = gen_entropy(20).unwrap();
        ent = with_checksum(ent.as_slice(), 1, StandardMnemonic::size15());
        let res = get_indexes(&ent, StandardMnemonic::size15());
        assert!(res.is_ok());

        let mut indexes = res.unwrap();
        assert_eq!(indexes.len(), 15);

        indexes = indexes.into_iter().filter(|v| *v > 2048).collect();
        assert_eq!(indexes.len(), 0);
    }

    #[test]
    fn should_generate_indexes_18words() {
        let mut ent = gen_entropy(24).unwrap();
        ent = with_checksum(ent.as_slice(), 1, StandardMnemonic::size18());
        let res = get_indexes(&ent, StandardMnemonic::size18());
        assert!(res.is_ok());

        let mut indexes = res.unwrap();
        assert_eq!(indexes.len(), 18);

        indexes = indexes.into_iter().filter(|v| *v > 2048).collect();
        assert_eq!(indexes.len(), 0);
    }

    #[test]
    fn should_generate_indexes_21words() {
        let mut ent = gen_entropy(28).unwrap();
        ent = with_checksum(ent.as_slice(), 1, StandardMnemonic::size21());
        let res = get_indexes(&ent, StandardMnemonic::size21());
        assert!(res.is_ok());

        let mut indexes = res.unwrap();
        assert_eq!(indexes.len(), 21);

        indexes = indexes.into_iter().filter(|v| *v > 2048).collect();
        assert_eq!(indexes.len(), 0);
    }

    #[test]
    fn should_generate_indexes_24words() {
        let mut ent = gen_entropy(32).unwrap();
        ent = with_checksum(ent.as_slice(), 1, StandardMnemonic::size24());
        let res = get_indexes(&ent, StandardMnemonic::size24());
        assert!(res.is_ok());

        let mut indexes = res.unwrap();
        assert_eq!(indexes.len(), 24);

        indexes = indexes.into_iter().filter(|v| *v > 2048).collect();
        assert_eq!(indexes.len(), 0);
    }

    #[test]
    fn should_fail_generate_indexes() {
        let res = get_indexes(&vec![0u8, 1u8], StandardMnemonic::size24());
        assert!(res.is_err())
    }

    #[test]
    fn get_index_24() {
        let mut entropy =
            Vec::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        entropy.push(0b01100110);
        let res = get_indexes(entropy.as_slice(), StandardMnemonic::size24()).unwrap();
        let exp: Vec<usize> = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 102,
        ];
        assert_eq!(res, exp);

        let mut entropy =
            Vec::from_hex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
                .unwrap();
        entropy.push(0b00010111);
        let res = get_indexes(entropy.as_slice(), StandardMnemonic::size24()).unwrap();
        let exp: Vec<usize> = vec![
            1019, 2015, 1790, 2039, 1983, 1533, 2031, 1919, 1019, 2015, 1790, 2039, 1983, 1533,
            2031, 1919, 1019, 2015, 1790, 2039, 1983, 1533, 2031, 1815,
        ];

        assert_eq!(res, exp);
    }

    #[test]
    fn get_index_18() {
        let entropy = Vec::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffd1").unwrap();
        let res = get_indexes(entropy.as_slice(), StandardMnemonic::size18()).unwrap();
        let exp: Vec<usize> = vec![
            2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047,
            2047, 2047, 2047, 2001,
        ];

        assert_eq!(res, exp);
    }

    #[test]
    fn should_convert_to_seed() {
        let entropy = StandardMnemonic::size24().entropy().unwrap();
        let mnemonic = Mnemonic::from_entropy(Language::English, &entropy).unwrap();

        let seed = mnemonic.seed(Some("12345"));
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn should_convert_to_sentence() {
        let entropy = StandardMnemonic::size24().entropy().unwrap();
        let mnemonic = Mnemonic::from_entropy(Language::English, &entropy).unwrap();
        let s: Vec<String> = mnemonic
            .sentence()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(s, mnemonic.words)
    }

    #[test]
    fn should_generate_english_mnemonic() {
        let entropy = vec![0u8; 32];
        let res = Mnemonic::from_entropy(Language::English, &entropy);
        assert!(res.is_ok());

        let mnemonic = res.unwrap();
        assert_eq!(
            mnemonic.sentence(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon art"
        );

        let entropy = mnemonic.seed(Some("TREZOR"));
        assert_eq!(
            entropy,
            Vec::from_hex(
                "bda85446c68413707090a52022edd26a\
                 1c9462295029f2e60cd7c4f2bbd309717\
                 0af7a4d73245cafa9c3cca8d561a7c3de6\
                 f5d4a10be8ed2a5e608d68f92fcc8"
            )
            .unwrap()
        );
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
        assert_eq!(
            mnemonic.seed(Some("TREZOR")),
            Vec::from_hex(
                "274ddc525802f7c828d8ef7ddbcdc530\
                 4e87ac3535913611fbbfa986d0c9e547\
                 6c91689f9c8a54fd55bd38606aa6a859\
                 5ad213d4c9c9f9aca3fb217069a41028"
            )
            .unwrap()
        );
    }

    #[test]
    fn should_be_compatible_with_bip39js() {
        let s = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about";
        let mnemonic = Mnemonic::try_from(Language::English, s).unwrap();

        assert_eq!(
            mnemonic.seed(Some("TREZOR")),
            Vec::from_hex(
                "c55257c360c07c72029aebc1b53c05ed03\
                 62ada38ead3e3e9efa3708e53495531f0\
                 9a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            )
            .unwrap()
        );
    }

    #[test]
    fn should_be_compatible_with_bip39js_emptypass() {
        let s = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about";
        let mnemonic = Mnemonic::try_from(Language::English, s).unwrap();

        assert_eq!(
            mnemonic.seed(None),
            Vec::from_hex(
                "5eb00bbddcf069084889a8ab9155568165f5c4\
                 53ccb85e70811aaed6f6da5fc19a5ac40b3\
                 89cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
            )
            .unwrap()
        );
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
        assert_eq!(
            mnemonic.seed(Some("TREZOR")),
            Vec::from_hex(
                "b15509eaa2d09d3efd3e006ef42151b3\
                 0367dc6e3aa5e44caba3fe4d3e352e65\
                 101fbdb86a96776b91946ff06f8eac59\
                 4dc6ee1d3e82a42dfe1b40fef6bcc3fd"
            )
            .unwrap()
        );
    }

    #[test]
    fn should_create_from_sentence_15() {
        let s = "hover involve coyote admit barrel lawsuit near genuine divide ghost music episode dish churn castle";
        let mnemonic = Mnemonic::try_from(Language::English, s).unwrap();
        let w: Vec<String> = s
            .to_string()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(mnemonic.words, w);
        assert_eq!(mnemonic.seed(None), Vec::from_hex(
            "455f5de41e8ec000a32c26c3f411903020269f70fef532aed49f9a1f9cf1a300752f476bd88764449e9b5728b5a67020b5536b60947bf1123a4a6e100845afc6"
        ).unwrap());
        assert_eq!(mnemonic.seed(Some("test")), Vec::from_hex(
            "a49a8045f542196e4d0c8af8bd9e80853bb4582db8df4d57fda69d5301fc2b65d984b4c8fa6d374e1507b4c30972d7950c5390e239f27961f79396974e600eef"
        ).unwrap());
    }

    #[test]
    fn should_create_from_entropy_15() {
        let entropy = Vec::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let mnemonic = Mnemonic::from_entropy(Language::English, entropy.as_slice()).unwrap();
        let words: Vec<String> =
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"
                .split_whitespace()
                .map(|w| w.to_string())
                .collect();

        assert_eq!(mnemonic.words, words);
        assert_eq!(hex::encode(mnemonic.seed(None)),
                   "d2911131a6dda23ac4441d1b66e2113ec6324354523acfa20899a2dcb3087849264e91f8ec5d75355f0f617be15369ffa13c3d18c8156b97cd2618ac693f759f"
        );
    }

    #[test]
    fn should_create_from_entropy_18() {
        let entropy = vec![0; 24];
        let mnemonic = Mnemonic::from_entropy(Language::English, entropy.as_slice()).unwrap();
        let words: Vec<String> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(mnemonic.words, words);
        assert_eq!(hex::encode(mnemonic.seed(None)),
                   "4975bb3d1faf5308c86a30893ee903a976296609db223fd717e227da5a813a34dc1428b71c84a787fc51f3b9f9dc28e9459f48c08bd9578e9d1b170f2d7ea506"
        );

        let entropy = Vec::from_hex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let mnemonic = Mnemonic::from_entropy(Language::English, entropy.as_slice()).unwrap();
        let words: Vec<String> = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(mnemonic.words, words);
        assert_eq!(hex::encode(mnemonic.seed(None)),
                   "b059400ce0f55498a5527667e77048bb482ff6daa16c37b4b9e8af70c85b3f4df588004f19812a1a027c9a51e5e94259a560268e91cd10e206451a129826e740"
        );

        let entropy = Vec::from_hex("808080808080808080808080808080808080808080808080").unwrap();
        let mnemonic = Mnemonic::from_entropy(Language::English, entropy.as_slice()).unwrap();
        let words: Vec<String> = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always"
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(mnemonic.words, words);
        assert_eq!(hex::encode(mnemonic.seed(None)),
                   "04d5f77103510c41d610f7f5fb3f0badc77c377090815cee808ea5d2f264fdfabf7c7ded4be6d4c6d7cdb021ba4c777b0b7e57ca8aa6de15aeb9905dba674d66"
        );

        let entropy = Vec::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let mnemonic = Mnemonic::from_entropy(Language::English, entropy.as_slice()).unwrap();
        let words: Vec<String> =
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"
                .split_whitespace()
                .map(|w| w.to_string())
                .collect();

        assert_eq!(mnemonic.words, words);
        assert_eq!(hex::encode(mnemonic.seed(None)),
                   "d2911131a6dda23ac4441d1b66e2113ec6324354523acfa20899a2dcb3087849264e91f8ec5d75355f0f617be15369ffa13c3d18c8156b97cd2618ac693f759f"
        );
    }

    #[test]
    fn should_create_from_entropy_24() {
        let entropy =
            Vec::from_hex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
                .unwrap();
        let mnemonic = Mnemonic::from_entropy(Language::English, entropy.as_slice()).unwrap();
        let words: Vec<String> = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();

        assert_eq!(mnemonic.words, words);
        assert_eq!(hex::encode(mnemonic.seed(None)),
                   "761914478ebf6fe16185749372e91549361af22b386de46322cf8b1ba7e92e80c4af05196f742be1e63aab603899842ddadf4e7248d8e43870a4b6ff9bf16324"
        );
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

    #[test]
    fn checksum_for_15() {
        let value = Vec::from_hex("ffffffffffffffffffffffffffffffffffffffff").unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size15());
        assert_eq!(act, 0b10011);
    }

    #[test]
    fn checksum_for_18() {
        let value = Vec::from_hex("000000000000000000000000000000000000000000000000").unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size18());
        assert_eq!(act, 0b100111);

        let value = Vec::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size18());
        assert_eq!(act, 0b010001);

        let value = Vec::from_hex("dd3e87806994a424a6161109bdbe195f585598e5f090b66a").unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size18());
        assert_eq!(act, 0b001011);

        let value = Vec::from_hex("f526453799d708306056bf170f640efd8cb9b8cc139df865").unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size18());
        assert_eq!(act, 0b111011);
    }

    #[test]
    fn checksum_for_21() {
        let value =
            Vec::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size21());
        assert_eq!(act, 0b0011001);

        let value =
            Vec::from_hex("1205c0b2e048ceef790d0433a902a070d0744af9b5e88edf7923c561").unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size21());
        assert_eq!(act, 0b0011011);

        let value =
            Vec::from_hex("b579f8e1dfc739a36a90a1f94cb33aef1bc28f43dc3533c829d5e935").unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size21());
        assert_eq!(act, 0b0000000);

        let value =
            Vec::from_hex("b579f8e1dfc739a36a90a1f94cb33aef1bc28f43dc3533c829d5e95c").unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size21());
        assert_eq!(act, 0b0000001);
    }

    #[test]
    fn checksum_for_24() {
        let value =
            Vec::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size24());
        assert_eq!(act, 0b10101111);

        let value =
            Vec::from_hex("e28a37058c7f5112ec9e16a3437cf363a2572d70b6ceb3b69654476253ed12fa")
                .unwrap();
        let act = checksum(value.as_slice(), StandardMnemonic::size24());
        assert_eq!(act, 0b10111111);
    }
}
