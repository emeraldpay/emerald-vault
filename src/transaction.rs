//!
//! Transaction structure
//!

use address::Address;
use crypto::digest::Digest;
use crypto::sha3::{Sha3, Sha3Mode};
use keystore::KeyFile;
use rlp::{RLPList, WriteRLP};

type U256 = [u8; 32];

/// Transaction data
pub struct Transaction<'a> {
    /// Nonce
    nonce: u64,

    /// Gas Price
    gas_price: U256,

    /// Gas Limit
    gas_limit: u64,

    /// Target address, or None to create contract
    to: Option<Address>,

    /// Value transferred with transaction
    value: U256,

    /// Data transferred with transaction
    data: &'a [u8],
}

impl<'a> Transaction<'a> {
    fn data_to_rlp(&self) -> RLPList {
        let mut data = RLPList::default();
        data.push(&self.nonce);
        data.push(&self.gas_price.to_vec());
        data.push(&self.gas_limit);
        data.push(&self.to.map(|x| x.to_vec()));
        data.push(&self.value.to_vec());
        data.push(&self.data.to_vec());
        data
    }

    fn hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let mut sha3 = Sha3::new(Sha3Mode::Keccak256);

        let mut rlp = Vec::new();
        let data = self.data_to_rlp();
        data.write_rlp(&mut rlp);

        sha3.input(rlp.as_slice());
        sha3.result(&mut hash);
        hash
    }

    fn sign(&self, passphrase: &str, key: &KeyFile) -> Result<Vec<u8>, ()> {
        match key.sign(&self.hash(), passphrase) {
            Ok(sign) => {
                let mut rlp = Vec::new();
                let mut data = self.data_to_rlp();

                let mut r = Vec::with_capacity(32);
                r.extend_from_slice(&sign[0..33]);
                data.push(&r);
                let mut s = Vec::with_capacity(32);
                s.extend_from_slice(&sign[32..64]);
                data.push(&s);
                let v = sign[63] + 27;
                data.push(&v);

                data.write_rlp(&mut rlp);
                Ok(rlp)
            }
            Err(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Transaction;
    use keystore::{Cipher, Kdf, KeyFile, Prf};
    use rustc_serialize::hex::FromHex;
    use std::str::FromStr;
    use uuid::Uuid;

    fn as_16bytes(hex: &str) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(hex.from_hex().unwrap().as_slice());
        buf
    }

    fn as_32bytes(hex: &str) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(hex.from_hex().unwrap().as_slice());
        buf
    }

    #[test]
    fn do_basic_sign() {
        let tx = Transaction {
            nonce: 101,
            gas_price: [0u8; 32],
            gas_limit: 100000,
            to: None,
            value: [0u8; 32],
            data: &[0u8; 0],
        };

        let key = KeyFile {
            uuid: Uuid::from_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap(),
            address: None,
            cipher_iv: as_16bytes("6087dab2f9fdbbfaddc31a909735c1e6"),
            cipher_text: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
                .from_hex()
                .unwrap(),
            kdf: Kdf::Pbkdf2 {
                c: 262144,
                prf: Prf::HmacSha256,
            },
            kdf_salt:
                as_32bytes("ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"),
            keccak256_mac:
                as_32bytes("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"),
            dk_length: 32,
            cipher: Cipher::Aes256Ctr,
            name:None,
            meta:None,
        };

        let act = tx.sign("testpassword", &key);
        assert!(act.is_ok());
        assert!(act.unwrap().len() > 32);
    }
}
