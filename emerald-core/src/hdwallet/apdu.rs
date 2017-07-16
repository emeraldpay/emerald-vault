//! # APDU for communication over HID

use std::convert::Into;

///
pub const APDU_DATA_MAX_SIZE: u8 = 255;

///
pub struct Command {
    CLA: u8,
    INS: u8,
    P1: u8,
    P2: u8,
    Lc: Vec<u8>,
    data: Vec<u8>,
    Le: Vec<u8>,
}

///
pub struct Response {
    data: Vec<u8>,
    SW1: u8,
    SW2: u8,
}

///
pub struct APDU_Builder;


impl APDU_Builder {
    ///
    pub fn get_address() -> Command {
        Command {
            CLA: 0xe0,
            INS: 0x02,
            P1: 0x00,
            P2: 0x00,
            Lc: vec![],
            data: vec![],
            Le: vec![],
        }
    }
}
