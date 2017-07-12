//! # Module to work with `HD Wallets`
//!
//! `HD(Hierarchical Deterministic) Wallet` specified in
//! [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.medёiawiki)


mod error;
mod apdu;
mod hd_keystore;

pub use u2fhid;
pub use self::error::Error;
use self::apdu;

/// Model of HD wallet
pub enum HDWallet_Type {
    Ledger_Nano_S,
}


/// Sign `RLP` encoded transaction with HD wallet
pub fn sign_tr(rlp_tr: Vec<u8>) -> Result<Vec<u8>, Error> {

}