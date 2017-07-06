//! # Module to work wih `HD Wallets `
//!
//! `HD(Hierarchical Deterministic) Wallet` specified in
//! [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.medёiawiki)

// crypto: { cipher: "hardware", hardware: "ledger-s:v1", hd: "0'/0/0"}

mod error;

pub use self::error::Error;

#[derive(Clone, Debug, Eq)]
pub struct HDWallet_Keyfile {
    /// Specifies if `Keyfile` is visible
    pub visible: Option<bool>,

    /// User specified name
    pub name: Option<String>,

    /// User specified description
    pub description: Option<String>,

    /// Address
    pub address: Address,

    /// UUID v4
    pub uuid: Uuid,

    /// Cipher type
    pub cipher: String,

    ///
    pub hardware: HDWallet_Type,

    ///
    pub hd_path: String,

}

/// Model of HD wallet
pub enum HDWallet_Type {
    Ledger_Nano_S,
}

impl Default for HDWallet_Ciphe {
    fn default() -> Self {
        Cipher::Ledger_Nano_S
    }
}

impl FromStr for HDWallet_Cipher {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == AES128_CTR_CIPHER_NAME => Ok(HDWallet_C),
            _ => Err(Error::HDWalletError()(s.to_string())),
        }
    }
}
