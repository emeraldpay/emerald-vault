//! # Module to work with `HD Wallets`
//!
//! `HD(Hierarchical Deterministic) Wallet` specified in
//! [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.medёiawiki)

extern crate base64;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::io;
use std::sync::mpsc::channel;

mod error;
mod apdu;
mod hd_keystore;
mod ledger;

pub use self::error::Error;
use self::ledger::Ledger;
use core::Address;
use core::Transaction;
use u2fhid::{self, U2FManager, to_u8_array};
use uuid::Uuid;
use self::ledger::DERIVATION_PATH;

/// Model of HD wallet
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletType {
    ///
    LedgerNanoS,
}

#[repr(packed)]
#[allow(dead_code)]
pub struct APDUHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub lc: u8,
}

pub trait WalletCore: Sized {
    ///
    fn sign_tx(&self, tr: &Vec<u8>, u2f: &U2FManager) -> Result<Vec<u8>, Error>;

    ///
    fn get_address(&self, u2f: &U2FManager) -> Result<Vec<u8>, Error>;
}

///
struct HDWallet<T: WalletCore> {
    u2f: u2fhid::U2FManager,
    id: WalletType,
    core: T,
}

impl HDWallet<Ledger> {
    ///
    pub fn create_ledger() -> Result<Self, Error> {
        Ok(HDWallet::<Ledger> {
            u2f: U2FManager::new()?,
            id: WalletType::LedgerNanoS,
            core: Ledger,
        })
    }
}

impl<T: WalletCore> HDWallet<T> {
    ///
    pub fn sign(&self, tr: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.core.sign_tx(tr, &self.u2f)
    }

    ///
    pub fn get_address(&self) -> Result<Vec<u8>, Error> {
        self.core.get_address(&self.u2f)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    pub fn should_sign_with_ledger() {
        let tx = Transaction {
            nonce: 0,
            gas_price: /* 21000000000 */
            to_32bytes("0000000000000000000000000000000\
                                          0000000000000000000000004e3b29200"),
            gas_limit: 21000,
            to: Some("0x0000000000000000000000000000000012345678"
                .parse::<Address>()
                .unwrap()),
            value: /* 1 ETC */
            to_32bytes("00000000000000000000000000000000\
                                          00000000000000000de0b6b3a7640000"),
            data: Vec::new(),
        };

        /*
            {
               "nonce":"0x00",
               "gasPrice":"0x04e3b29200",
               "gasLimit":"0x5208",
               "to":"0x0000000000000000000000000000000012345678",
               "value":"0x0de0b6b3a7640000",
               "data":"",
               "chainId":61
            }
        */
        println!("RLP packed transaction: {:?}", &tx.hash(61));

        let wallet = HDWallet::create_ledger().unwrap();
        println!("signed with wallet {:?}", wallet.sign(&tx.hash(61).to_vec()).unwrap());
    }

    #[test]
    pub fn should_get_address_with_ledger() {
        let wallet = HDWallet::create_ledger().unwrap();
        println!("Address {:?}", wallet.get_address().unwrap());

        println!("Asking a security key to register now...");
        let mut challenge = Sha256::new();
        challenge.input_str(r#"{"challenge": "1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70",
                                "version": "U2F_V2", "appId": "http://demo.yubico.com"}"#);
        let mut chall_bytes: Vec<u8> = vec![0; challenge.output_bytes()];
        challenge.result(&mut chall_bytes);

        let mut application = Sha256::new();
        application.input_str("http://demo.yubico.com");
        let mut app_bytes: Vec<u8> = vec![0; application.output_bytes()];
        application.result(&mut app_bytes);

        let manager = U2FManager::new().unwrap();
        let header = APDUHeader {
            cla: 0xe0,
            ins: 0x02,
            p1: 0x00,
            p2: 0x00,
            lc: 21,
        };
        let header_raw = to_u8_array(&header);
        let mut apdu = vec![0u8; 26];
        apdu[0..5].clone_from_slice(&header_raw);
        apdu[5..26].clone_from_slice(&DERIVATION_PATH);

        let (tx, rx) = channel();
        manager
            .sign(15, chall_bytes, app_bytes, apdu, move |rv| {
                tx.send(rv.unwrap()).unwrap();
            })
            .unwrap();

        let sign_data = rx.recv().unwrap();
        println!("Sign result: {}", base64::encode(&sign_data));
        println!("Done.");
    }
}
