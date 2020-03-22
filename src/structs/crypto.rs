use crate::structs::types::IsVerified;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScryptKdf {
    pub dklen: u32,
    pub salt: Vec<u8>,
    pub n: u32,
    pub r: u32,
    pub p: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pbkdf2 {
    pub dklen: u32,
    pub c: u32,
    pub salt: Vec<u8>,
    pub prf: PrfType,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PrfType {
    HmacSha256,
    HmacSha512,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Kdf {
    Scrypt(ScryptKdf),
    Pbkdf2(Pbkdf2),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Encrypted {
    pub cipher: Cipher,
    pub kdf: Kdf,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Cipher {
    Aes128Ctr(Aes128CtrCipher),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Aes128CtrCipher {
    pub encrypted: Vec<u8>,
    pub iv: Vec<u8>,
    pub mac: MacType,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MacType {
    Web3(Vec<u8>),
}

impl Encrypted {
    pub fn get_mac(&self) -> &Vec<u8> {
        match &self.cipher {
            Cipher::Aes128Ctr(v) => match &v.mac {
                MacType::Web3(x) => x,
            },
        }
    }

    pub fn get_iv(&self) -> &Vec<u8> {
        match &self.cipher {
            Cipher::Aes128Ctr(v) => &v.iv,
        }
    }

    pub fn get_message(&self) -> &Vec<u8> {
        match &self.cipher {
            Cipher::Aes128Ctr(v) => &v.encrypted,
        }
    }
}

impl IsVerified for ScryptKdf {
    fn verify(self) -> Result<Self, String> {
        if self.salt.len() != 32 {
            return Err("salt has invalid size".to_string());
        }
        if self.dklen != 32 {
            return Err("dklen has invalid value".to_string());
        }
        if self.p <= 0 {
            return Err("p is too small".to_string());
        }
        if self.n <= 0 {
            return Err("n is too small".to_string());
        }
        if self.r <= 0 {
            return Err("r is too small".to_string());
        }
        Ok(self)
    }
}
