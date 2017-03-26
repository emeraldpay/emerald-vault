use byteorder::{WriteBytesExt, BigEndian};
use tiny_keccak::Keccak;
use secp256k1;
use secp256k1::key::{SecretKey, PublicKey};
use std::collections::HashMap;

lazy_static! {
	pub static ref SECP256K1: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}

pub trait Encodable {
    fn to_bytes(&self, out: &mut Vec<u8>);
}

impl Encodable for usize {
    fn to_bytes(&self, out: &mut Vec<u8>) {
        let val = *self as u64;
        let len = 8 - val.leading_zeros() / 8;

        for i in 0..len {
            let j = len - 1 - i;
            out.push((*self >> (j * 8)) as u8);
        }
    }
}

///Signature for transaction.
pub struct Signature {
    pub s: [u8; 32],
    pub r: [u8; 32],
    pub v: [u8; 1],
}

impl Signature {
    fn new(&data: [u8]) -> Result<Self, Error> {
        Ok(Signature {
            r: data[0..32],
            s: data[33..64],
            v: data[64],
        })
    }
}

/// Encoder for RLP compression.
pub trait Encoder {

    fn encode() -> [u8; 32];

    /// Compressing of simple values.
    fn encode_raw_bytes(data: &[u8], out: &mut Vec<u8>) {
        match data.len() {
            0 => { out.push(0x00); }
            1 => {
                if data[0] < 0x80 {
                    out.push(data[0]);
                } else {
                    out.extend([0x81, data[0]].iter().cloned());
                }
            }
            len @ 2...55 => {
                out.push(0x80 + len as u8);
                out.extend(data.iter().cloned());
            }
            len => {
                let mut len_bytes = vec![];
                len.to_bytes(&mut len_bytes);

                out.push(0xb7 + len_bytes.len() as u8);
                out.extend(len_bytes.iter().cloned());
                out.extend(data.iter().cloned());
            }
        }
    }

    /// Compressing items of containers (nested values).
    fn encode_nested_bytes(data: &[u8], out: &mut Vec<u8>) {
        match data.len() {
            0...55 => {
                out.push(0x80 + len as u8);
                out.extend(data.iter().cloned());
            }
            _ => {
                let mut len_bytes = vec![];
                len.to_bytes(&mut len_bytes);

                out.push(0xb7 + len_bytes.len() as u8);
                out.extend(len_bytes.iter().cloned());
                out.extend(data.iter().cloned());
            }
        }
    }
}

pub struct Transaction {
    pub from: U256,
    pub to: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub value: U256,
    pub data: Bytes,
    pub nonce: U256,
}

impl Encoder for Transaction {
    fn encode() -> [u8] {

    }
}

impl Transaction {
    fn new(args: &HashMap<String, Item>) -> Self {
        let mut tr = Transaction();
        for (arg, val) in &args {
            match arg {
                "from" => {tr.from = val;}
                "to" => {tr.to = val;}
                "gas_price" => {tr.gas_price = val;}
                "gas" => {tr.gas = val;}
                "value" => {tr.val = val;}
                "data" => {tr.data = val;}
                "nonce" => {tr.nonce = val;}
                _ => {}
            }
        }

        tr
    }

}

fn hash(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Keccak::new_sha3_256();

    sha3.update(data);

    let mut res: [u8; 32] = [0; 32];
    sha3.finalize(&mut res);
    res
}

fn sign (message: &[u8], private_key: &[u8]) -> Result<Signature, Error> {
    let context = &SECP256K1;
    let sec = SecretKey::from_slice(context, &secret)?;
    let s = context.sign_recoverable(&SecpMessage::from_slice(&message[..])?, &sec)?;
    let (rec_id, data) = s.serialize_compact(context);
    let mut sig_data = [0; 65];

    sig_data[0..64].copy_from_slice(&data[0..64]);
    sig_data[64] = rec_id.to_i32() as u8;

    Signature::new(sig_data)
}

#[cfg(test)]
mod tests {
    use super::{Transaction, hash, sign};
    static tr_args: HashMap<> = HashMap::

    #[test]
    fn should_rlp_compress() {
        let data = vec![0x00];
        let mut out = vec!();
        rlp(&data, &mut out);
        assert_eq!(data, out);

        let data = vec![0x7F];
        let mut out = vec!();
        rlp(&data, &mut out);
        assert_eq!(data, out);

        let data = vec![0x80];
        let compressed = vec![0x81, 0x80];
        let mut out = vec!();
        rlp(&data, &mut out);
        assert_eq!(compressed, out);

        let mut data = vec!();
        let mut compressed = vec![0xB9, 0x04, 0x00];
        for i in 0..1024 {
            data.push(i as u8);
            compressed.push(i as u8);
        }
        let mut out = vec!();
        rlp(&data, &mut out);
        assert_eq!(compressed, out);
    }

    #[test]
    fn should_sign() {
        let tr = Transaction::new(tr_args);
        let key: [u8; 32] = [0; 32];

        assert_eq!(vec![0], sign(hash(tr.encode()), key));
    }

}