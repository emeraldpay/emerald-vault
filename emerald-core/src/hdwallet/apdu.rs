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
//
//impl Into<Vec<u8>> for Command {
//    fn into(self) -> Vec<u8> {
//        let mut buf = Vec::new();
//        buf.push(self.CLA);
//        buf.push(self.INS);
//        buf.push(self.P1);
//        buf.push(self.P2);
//
//        buf.append(&self.Lc);
//        buf.append(&self.data);
//        buf.append(&self.Le);
//
//        buf
//    }
//}
