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
//! # `Language` for mnemonic codes
//!

static BIP39_ENGLISH: &'static str = include_str!("bip39_english.txt");
lazy_static! {
    /// List of words for `English` language
    pub static ref BIP39_ENGLISH_WORDLIST: Vec<String> = gen_wordlist(BIP39_ENGLISH);
}

/// Language of dictionary for mnemonic generation
#[derive(Debug, Clone, Copy)]
pub enum Language {
    /// English language
    English,
}

impl Language {
    /// Get list of word sor specific `Language`
    pub fn wordlist(&self) -> &'static Vec<String> {
        match *self {
            Language::English => &BIP39_ENGLISH_WORDLIST,
        }
    }
}

impl Default for Language {
    fn default() -> Language {
        Language::English
    }
}

fn gen_wordlist(lang_words: &str) -> Vec<String> {
    lang_words.split_whitespace().map(|s| s.into()).collect()
}
