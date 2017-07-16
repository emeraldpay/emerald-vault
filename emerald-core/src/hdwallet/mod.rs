//! # Module to work with `HD Wallets`
//!
//! Currently supports only Ledger Nano S & Ledger Blue
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
mod comm;

pub use self::error::Error;
use core::Address;
use core::Transaction;
use u2fhid::{self, to_u8_array, RunLoop, Monitor, Device};
use uuid::Uuid;

pub const GET_ETH_ADDRESS: u8 = 0x02;
pub const SIGN_ETH_TRANSACTION: u8 = 0x04;
pub const APDU_HEADER_SIZE: u8 = 0x05;

#[repr(packed)]
#[derive(Debug, Clone)]
pub struct APDU {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub len: u8,
    pub data: Vec<u8>
}

impl Default for APDU {
    fn default() -> Self {
        APDU {
            cla: 0xe0,
            ins: 0x00,
            p1: 0x00,
            p2: 0x00,
            len: 0x00,
            data: vec!(),
        }
    }
}

impl APDU {
    pub const HEADER_SIZE: u8 = 0x05;

    pub fn raw_header(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(APDU::HEADER_SIZE);
        buf.push(self.cla);
        buf.push(self.ins);
        buf.push(self.p1);
        buf.push(self.p2);
        buf.push(self.len);
        buf
    }

    pub fn len(&self) -> usize {
        self.data.len() + APDU::HEADER_SIZE
    }

}

pub struct APDU_Builder{
    apdu: APDU,
}

impl APDU_Builder {
    pub fn get_empty<'a>(&'a mut self, cmd: u8) -> &'a mut Self {
        self.apdu = APDU::default();
        self
    }

    pub fn with_data<'a>(&'a mut self, data: Vec<u8>) -> &'a mut Self {
        self.apdu.data = data;
        self.apdu.len = data.len() as u8;
        self
    }

    pub fn with_p1<'a>(&'a mut self, p1: u8) -> &'a mut Self {
        self.apdu.p1 = p1;
        self
    }

    pub fn with_p2<'a>(&'a mut self, p2: u8) -> &'a mut Self {
        self.apdu.p2 = p2;
        self
    }

    pub fn build(&self) -> APDU {
        self.apdu
    }
}

///
pub struct WManager {
    devices: Vec<Device>,
}

impl WManager {
    pub fn new() -> Self {

    }

    pub fn get_address(dev: Device) -> Result<Address, Error> {

    }

    pub fn sign_transaction(dev: Device, tr: Vec<u8>) -> Result<Vec<u8>, Error> {

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
        let manager = WManager::new();
        let device = manager.devices[0];

        println!("Address: {}",  WManager::get_address(device));
    }
}
