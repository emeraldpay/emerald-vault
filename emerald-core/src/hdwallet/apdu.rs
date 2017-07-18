//! # APDU for communication over HID

///
#[repr(packed)]
#[derive(Debug, Clone)]
pub struct APDU {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub len: u8,
    pub data: Vec<u8>,
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
    pub const HEADER_SIZE: usize = 0x05;

    ///
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

///
pub struct ApduBuilder {
    apdu: APDU,
}

impl ApduBuilder {
    ///
    pub fn new(cmd: u8) ->  Self {
        let mut apdu = APDU::default();
        apdu.ins = cmd;

        Self {
            apdu: apdu
        }
    }

    ///
    pub fn with_p1<'a>(&'a mut self, p1: u8) -> &'a mut Self {
        self.apdu.p1 = p1;
        self
    }

    ///
    pub fn with_p2<'a>(&'a mut self, p2: u8) -> &'a mut Self {
        self.apdu.p2 = p2;
        self
    }

    ///
    pub fn with_data<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        self.apdu.data.extend_from_slice(data);
        self.apdu.len += data.len() as u8;
        self
    }

    ///
    pub fn build(&self) -> APDU {
        self.apdu.clone()
    }
}
