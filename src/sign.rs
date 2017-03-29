use tiny_keccak::Keccak;
use secp256k1;
use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::{Error, Message, RecoverableSignature, RecoveryId};
use std::collections::HashMap;
use num_bigint::{BigUint};
use rand::{Rng, thread_rng};

lazy_static! {
	pub static ref SECP256K1: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}

pub trait Encodable {
    fn encode(&self) -> Vec<u8>;
}

pub trait ToBytes {
    fn to_bytes(&self, out: &mut Vec<u8>);
}

impl ToBytes for usize {
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
    pub v: u8,
}

impl Signature {
    fn new(data: &[u8]) -> Result<Self, Error> {
        let mut r_val: [u8; 32] = [0u8; 32];
        let mut s_val: [u8; 32] = [0u8; 32];

        r_val.copy_from_slice(&data[0..32]);
        s_val.copy_from_slice(&data[32..64]);

        Ok(Signature {
            r: r_val,
            s: s_val,
            v: data[64],
        })
    }

    fn to_vec(&self) -> Vec<u8> {
        let res = [self.r, self.s].concat();
        res
    }
}



/// Encoder for RLP compression.
pub struct RlpEncoder;

impl RlpEncoder {
    /// Compressing of simple values.
    fn encode_raw_bytes (data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
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

        out
    }

    /// Compressing item of items sequence.
    fn encode_nested_bytes (data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        match data.len() {
            len @ 0...55 => {
                out.push(0xc0 + len as u8);
                out.extend(data.iter().cloned());
            }
            len @ _ => {
                let mut len_bytes = vec![];
                len.to_bytes(&mut len_bytes);

                out.push(0xf7 + len_bytes.len() as u8);
                out.extend(len_bytes.iter().cloned());
                out.extend(data.iter().cloned());
            }
        }

        out
    }
}

struct Transaction {
    nonce: BigUint,
    gas_price: BigUint,
    gas_limit: BigUint,
    to: BigUint,
    value: BigUint,
    pub data: Vec<u8>,
}

///Getter to extract first 32 bytes out of BigInt.
macro_rules! impl_getter {
    ($val: ident) => {
        pub fn $val(&self) -> Vec<u8> {
            let bytes = self.$val.to_bytes_be();
            bytes[0..32].to_vec();
            bytes
        }
    }
}

macro_rules! extract_bigint {
    ($args: expr, $val: expr) => {
        BigUint::from_bytes_be($args.get($val).unwrap())
    };
}

impl Transaction {

    impl_getter!(nonce);
    impl_getter!(gas_price);
    impl_getter!(gas_limit);
    impl_getter!(to);
    impl_getter!(value);

    pub fn new(args: &HashMap<&str, Vec<u8>>) -> Self {
        Transaction {
            nonce: extract_bigint!(args, "nonce"),
            gas_price: extract_bigint!(args, "gas_price"),
            gas_limit: extract_bigint!(args, "gas_limit"),
            to: extract_bigint!(args, "to"),
            value: extract_bigint!(args, "value"),
            data: args.get("data").unwrap().to_vec(),
        }
    }


}

impl Encodable for Transaction {
    fn encode(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();


        bytes.extend(&RlpEncoder::encode_raw_bytes(&self.nonce()));
        bytes.extend(&RlpEncoder::encode_raw_bytes(&self.gas_price()));
        bytes.extend(&RlpEncoder::encode_raw_bytes(&self.gas_limit()));
        bytes.extend(&RlpEncoder::encode_raw_bytes(&self.to()));
        bytes.extend(&RlpEncoder::encode_raw_bytes(&self.value()));
        bytes.extend(&RlpEncoder::encode_raw_bytes(&self.data));

        bytes
    }
}

fn kec(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Keccak::new_sha3_256();

    sha3.update(data);

    let mut res: [u8; 32] = [0; 32];
    sha3.finalize(&mut res);
    res
}

fn sign (message: &[u8], secret: &SecretKey) -> Result<Signature, Error> {
    let context = &SECP256K1;
    let sig = context.sign_recoverable(&Message::from_slice(message)?, &secret)?;
    let (rec_id, data) = sig.serialize_compact(context);
    let mut sig_data = [0; 65];

    sig_data[0..64].copy_from_slice(&data[0..64]);
    sig_data[64] = rec_id.to_i32() as u8;

    Ok(Signature::new(&sig_data)?)
}

fn recover(message: &[u8], signature: &Signature) -> Result<PublicKey, Error> {
    let context = &SECP256K1;
    let rsig = RecoverableSignature::from_compact(context, &signature.to_vec(), RecoveryId::from_i32(signature.v as i32)?)?;
    let pubkey = context.recover(&Message::from_slice(&message[..])?, &rsig)?;

    Ok(pubkey)
}


#[cfg(test)]
mod tests {
    use super::*;
    lazy_static! {
        static ref ARGS: HashMap<&'static str, Vec<u8>> = {
            let args: HashMap<&str, Vec<u8>> =  ["nonce", "gas_price", "gas_limit", "to", "value", "data"].iter()
            .map(|i| (*i, get_random()))
            .collect();
            args
        };
    }

    fn get_random() -> Vec<u8> {
        let mut msg = [0u8; 32].to_vec();
        thread_rng().fill_bytes(&mut msg);

        msg
    }

    #[test]
    fn should_rlp_raw() {
        let data = vec![0x00];
        assert_eq!(data, RlpEncoder::encode_raw_bytes(&data));

        let data = vec![0x7F];
        assert_eq!(data, RlpEncoder::encode_raw_bytes(&data));

        let data = vec![0x80];
        let compressed = vec![0x81, 0x80];
        assert_eq!(compressed, RlpEncoder::encode_raw_bytes(&data));

        let mut data = vec!();
        let mut compressed = vec![0xB9, 0x04, 0x00];
        for i in 0..1024 {
            data.push(i as u8);
            compressed.push(i as u8);
        }
        assert_eq!(compressed, RlpEncoder::encode_raw_bytes(&data));
    }


    #[test]
    fn should_create_transaction() {
        let tr = Transaction::new(&ARGS);

        let values: HashMap<&str, BigUint>= ARGS.iter()
            .filter(|&(k, _)|  *k != "data")
            .map(|(k, v)| (*k, BigUint::from_bytes_be(&v)))
            .collect();

        assert_eq!(tr.nonce, *values.get(&"nonce").unwrap());
        assert_eq!(tr.gas_price, *values.get(&"gas_price").unwrap());
        assert_eq!(tr.gas_limit, *values.get(&"gas_limit").unwrap());
        assert_eq!(tr.to, *values.get(&"to").unwrap());
        assert_eq!(tr.value, *values.get(&"value").unwrap());
        assert_eq!(tr.data, *ARGS.get(&"data").unwrap());


    }

    #[test]
    fn should_encode_transaction() {
        let tr = Transaction::new(&ARGS);
        let tr_encoded = &tr.encode();
        assert_eq!(tr_encoded[0], 0xa0);

        let keys_len = ARGS.keys().len();
        assert_eq!(tr_encoded.len(), keys_len*32 + keys_len);
    }

    #[test]
    fn should_sign() {
        let context = &SECP256K1;
        let (sk, _) = context.generate_keypair(&mut thread_rng()).unwrap();
        let tr_encoded = Transaction::new(&ARGS).encode();

        let sig = sign(&kec(&tr_encoded), &sk).unwrap();

        assert!(sig.r.len() == 32);
        assert!(sig.s.len() == 32);
    }

    #[test]
    fn should_recover() {
        let context = &SECP256K1;
        let message = get_random();
        let (sk, pk) = context.generate_keypair(&mut thread_rng()).unwrap();

        let sig = sign(&message, &sk).unwrap();

        assert_eq!(recover(&message, &sig), Ok(pk));
    }
}