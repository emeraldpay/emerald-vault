//! # Ledger wallet

use super::{Error, Transaction, WalletCore};
use super::u2fhid::{self, U2FAPDUHeader, to_u8_array, U2FManager};
use super::u2fhid::consts::{U2FAPDUHEADER_SIZE, U2FHID_MSG};
use std::mem;
use std::sync::mpsc::channel;

pub const LEDGER_CLA: u8 = 0xe0;
pub const LEDGER_GET_ADDRESS_INS: u8 = 0x02;
pub const LEDGER_SIGN_TX_INS: u8 = 0x04;

pub const DATA_CHUNK_SIZE: u8 = 255;
pub const DERIVATION_PATH: [u8; 21] =  [ 5,  0x80, 0, 0, 44,  0x80, 0, 0, 60,
    0x80, 0x02, 0x73, 0xd0,  0x80, 0, 0, 0,  0, 0, 0, 0 ];  // /44'/60'/160720'/0'/0'

///
pub struct Ledger;

///
pub struct PacketBuilder {

}

impl Ledger {
//    ///
//    pub fn sign_tx_header(p1: u8, len: usize) -> U2FAPDUHeader {
//        U2FAPDUHeader {
//            cla: LEDGER_CLA,
//            ins: LEDGER_SIGN_TX_INS,
//            p1: p1,
//            p2: 0x00,
//            lc: [0, (len >> 8) as u8, (len & 0xff) as u8],
//        }
//    }
//
//    ///
//    pub fn get_address_header(len: usize) -> U2FAPDUHeader {
//        U2FAPDUHeader {
//            cla: LEDGER_CLA,
//            ins: LEDGER_GET_ADDRESS_INS,
//            p1: 0x00,
//            p2: 0x00,
//            lc: [0, (len >> 8) as u8, (len & 0xff) as u8],
//        }
//    }
}

impl WalletCore for Ledger {
    /// [https://github.com/LedgerHQ/blue-app-eth/blob/master/doc/ethapp.asc#sign-eth-transaction]
    ///
    fn sign_tx(&self, tr: &Vec<u8>, u2f: &U2FManager) -> Result<Vec<u8>, Error> {
//        let (first, rest) = tr.split_at((DATA_CHUNK_SIZE - 1) as usize);

//        let mut header = Ledger::sign_tx_header(0x00, tr.len());
//        let mut header_raw: &[u8] = to_u8_array(&header);
//        let mut data_vec: Vec<u8> = vec![0; mem::size_of::<U2FAPDUHeader>() + tr.len() + 2];
//
//        data_vec[0..U2FAPDUHEADER_SIZE].clone_from_slice(&header_raw);
//        data_vec[U2FAPDUHEADER_SIZE..(tr.len() + U2FAPDUHEADER_SIZE)].clone_from_slice(&tr);
//
//        let (tx, rx) = channel();
//        u2f.send_raw(1000, data_vec, move |rv| {
//            let v = rv.unwrap();
//            println!(">> DEBUG first: {:?}", v );
//            tx.send(v).unwrap();
//        })?;
//        let mut res = rx.recv().unwrap();

//        for chunk in rest.chunks(DATA_CHUNK_SIZE as usize) {
//            let mut header = Ledger::sign_tx_header(0x80, chunk.len());
//            let mut header_raw = to_arr(&header);
//            let mut data_vec = vec![0; mem::size_of::<U2FAPDUHeader>() + chunk.len() + 2];
//            data_vec[0..U2FAPDUHEADER_SIZE].clone_from_slice(&header_raw);
//            data_vec[U2FAPDUHEADER_SIZE..(chunk.len() + U2FAPDUHEADER_SIZE)]
//                .clone_from_slice(&chunk);
//
//            let (tx, rx) = channel();
//            u2f.send_raw(1000, data_vec, move |rv| {
//                let v = rv.unwrap();
//                println!(">> DEBUG first: {:?}", v );
//                tx.send(v).unwrap();
//            })?;
//
//            res = rx.recv().unwrap();
//        }

//        Ok(res)
          unimplemented!()
    }

    ///
    fn get_address(&self, u2f: &U2FManager) -> Result<Vec<u8>, Error> {
        let (tx, rx) = channel();

        println!(">> DEBUG send_apdu get address");

        u2f.send_apdu(100, 0xE0, LEDGER_GET_ADDRESS_INS, 0x00, DERIVATION_PATH.to_vec(), move |rv| {
            let v = rv.unwrap();
            tx.send(v).unwrap();
        })?;

        Ok(rx.recv().unwrap())

    }
}