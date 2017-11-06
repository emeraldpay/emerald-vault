//! # Module to work with mnemonic codes
//!
//! Refer `BIP39` for detailed specification on mnemonic codes
//! [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)


#[derive(Debug, Copy, Clone)]
pub enum MnemonicSize {
    Size12,
    Size15,
    Size18,
    Size21,
    Size24
}

#[derive(Debug, Copy, Clone)]
pub struct Mnemonic {
    size: MnemonicSize,
    entropy: Vec<u8>,
    language: language
}