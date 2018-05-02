//! # APDU for communication with Ledger HD wallet over HID
//! For more details about protocol refer to
//! [APDU](https://github.com/LedgerHQ/blue-app-eth/blob/master/doc/ethapp.asc)

use std::fmt;

pub const APDU_HEADER_SIZE: usize = 0x05;

///
#[repr(packed)]
pub struct APDU {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub len: u8,
    pub data: Vec<u8>,
}

impl fmt::Debug for APDU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let d = vec![].clone_from(&self.data);
        write!(
            f,
            "APDU {{ cla: {}, ins: {}, p1: {}, p2: {}, len: {}, data: {:?} }}",
            self.cla, self.ins, self.p1, self.p2, self.len, d
        )
    }
}

impl Clone for APDU {
    fn clone(&self) -> APDU {
        APDU {
            cla: self.cla,
            ins: self.ins,
            p1: self.p1,
            p2: self.p2,
            len: self.len,
            data: self.data.clone(),
        }
    }
}

impl Default for APDU {
    fn default() -> Self {
        APDU {
            cla: 0xe0,
            ins: 0x00,
            p1: 0x00,
            p2: 0x00,
            len: 0x00,
            data: Vec::new(),
        }
    }
}

impl APDU {
    /// Get APDU's packed header
    pub fn raw_header(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(APDU_HEADER_SIZE);
        buf.push(self.cla);
        buf.push(self.ins);
        buf.push(self.p1);
        buf.push(self.p2);
        buf.push(self.len);
        buf
    }

    pub fn len(&self) -> usize {
        let len = self.data.len();
        len + APDU_HEADER_SIZE
    }
}

/// Builder for Ledger APDU
pub struct ApduBuilder {
    apdu: APDU,
}

#[allow(dead_code)]
impl ApduBuilder {
    ///  Create new Builder
    pub fn new(cmd: u8) -> Self {
        let mut apdu = APDU::default();
        apdu.ins = cmd;

        Self { apdu }
    }

    /// Add parameter 1
    pub fn with_p1(&mut self, p1: u8) -> &mut Self {
        self.apdu.p1 = p1;
        self
    }

    /// Add parameter 2
    pub fn with_p2(&mut self, p2: u8) -> &mut Self {
        self.apdu.p2 = p2;
        self
    }

    /// Add data
    pub fn with_data(&mut self, data: &[u8]) -> &mut Self {
        self.apdu.data.extend_from_slice(data);
        self.apdu.len += data.len() as u8;
        self
    }

    /// Create APDU
    pub fn build(&self) -> APDU {
        self.apdu.clone()
    }
}
