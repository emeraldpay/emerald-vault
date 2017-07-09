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

    /// Create array APDU for transaction signing
    /// Transaction is splitted among multiple APDUs
    /// if it size exceeds 255 bytes
    ///
    /// # Arguments:
    ///  tr - rlp encoded transaction
    ///  id - array fo derivation id
    ///
    pub fn sign_transaction(tr: Vec<u8>, id: Vec<u32>) -> Vec<Command> {
        let mut buf: Vec<Command> = Vec:new();
        let init_chunk_size = APDU_DATA_MAX_SIZE - id.len() * 4 + 1;

        let (head, tail) = tr.split_at(init_chunk_size);

        let mut data = Vec::new();
        data.push(id.len());
        data.append(&id);
        data.append(&head);

        buf.push( Command {
            CLA: 0xe0,
            INS: 0x04,
            P1: 0u8,
            P2: 0x00,
            Lc: vec![],
            data: data,
            Le: vec![],
        });

        for chunk in tail.chunks(APDU_MAX_SIZE) {
            buf.push( Command {
                CLA: 0xe0,
                INS: 0x04,
                P1: 80u8,
                P2: 0x00,
                Lc: vec![],
                data: chunk,
                Le: vec![],
            });
        }

        buf
    }
}

impl Into<Vec<u8>> for Command {
    fn into(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.CLA);
        buf.push(self.INS);
        buf.push(self.P1);
        buf.push(self.P2);

        buf.append(&self.Lc);
        buf.append(&self.data);
        buf.append(&self.Le);

        buf
    }
}