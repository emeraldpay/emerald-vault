use tiny_keccak::Keccak;
use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::{self, Error, Message, RecoverableSignature, RecoveryId};

lazy_static! {
	pub static ref SECP256K1: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}

/// Signature for transaction.
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
    use rand::{Rng, thread_rng};
    use transaction::Transaction;
    use std::collections::HashMap;

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
    fn should_sign() {
        let context = &SECP256K1;
        let (sk, _) = context.generate_keypair(&mut thread_rng()).unwrap();
        let tr_encoded: Vec<u8> = Transaction::new(&ARGS).into();

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