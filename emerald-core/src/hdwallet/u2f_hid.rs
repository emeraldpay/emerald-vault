///! # U2f over HID communication module

use super::Error;
use super::APDU;
use hidapi;

/// Size of packet in bytes
pub const PACKET_SIZE: u8 = 64;

/// Initialization packet
#[derive(Clone, Copy, Debug)]
pub struct InitPacket {
    CID: u32,
    CMD: u8,
    BCNT: u16,
    DATA: Vec<u8>
}

/// Continuation packet
#[derive(Clone, Copy, Debug)]
pub struct ContPacket {
    CID: u32,
    SEQ: u8,
    DATA: Vec<u8>
}

///
#[derive(Clone, Copy, Debug)]
pub struct U2F_Sequence {
    data: APDU,
};


impl U2F_Sequence {
    pub fn new(apdu: APDU) -> Self {
        U2F_Sequence {
            data: apdu,
        }
    }
}


pub fn send(data: Vec<u8>) -> Result<(), Error> {

}


