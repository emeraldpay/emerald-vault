//! # `Language` for mnemonic codes
//!

static BIP39_ENGLISH: &'static str = include_str!("bip39_english.txt");
lazy_static! {
	pub static ref BIP39_ENGLISH_WORDLIST: Vec<String> = { gen_wordlist(BIP39_ENGLISH) };
}


#[derive(Debug, Clone, Copy)]
pub enum Language {
    English,
}

impl Language {
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
