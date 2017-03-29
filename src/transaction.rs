use num_bigint::BigUint;
use std::collections::HashMap;
use util::RlpEncoder;

/// Transaction body, excluding signature fields.
pub struct Transaction {
    nonce: BigUint,
    gas_price: BigUint,
    gas_limit: BigUint,
    to: BigUint,
    value: BigUint,
    pub data: Vec<u8>,
}

/// Getter to extract first 32 bytes (big-endian) out of BigInt.
macro_rules! impl_getter {
    ($val: ident) => {
        pub fn $val(&self) -> Vec<u8> {
            let bytes = self.$val.to_bytes_be();
            bytes[0..32].to_vec();
            bytes
        }
    }
}

impl Transaction {
    impl_getter!(nonce);
    impl_getter!(gas_price);
    impl_getter!(gas_limit);
    impl_getter!(to);
    impl_getter!(value);

    pub fn new(args: &HashMap<&str, Vec<u8>>) -> Self {
        Transaction {
            nonce: BigUint::from_bytes_be(args.get("nonce").unwrap()),
            gas_price: BigUint::from_bytes_be(args.get("gas_price").unwrap()),
            gas_limit: BigUint::from_bytes_be(args.get("gas_limit").unwrap()),
            to: BigUint::from_bytes_be(args.get("to").unwrap()),
            value: BigUint::from_bytes_be(args.get("value").unwrap()),
            data: args.get("data").unwrap().to_vec(),
        }
    }
}

impl Into<Vec<u8>> for Transaction {
    fn into(self) -> Vec<u8> {
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


#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};

    lazy_static! {
        static ref ARGS: HashMap<&'static str, Vec<u8>> = {
            let args: HashMap<&str, Vec<u8>> =  [
                "nonce", "gas_price", "gas_limit", "to", "value", "data"
            ].iter()
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
    fn should_create_transaction() {
        let tr = Transaction::new(&ARGS);

        let values: HashMap<&str, BigUint> = ARGS.iter()
            .filter(|&(k, _)| *k != "data")
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
    fn should_sized_fields() {
        let tr = Transaction::new(&ARGS);

        assert_eq!(tr.nonce(), *ARGS.get(&"nonce").unwrap());
        assert_eq!(tr.gas_price(), *ARGS.get(&"gas_price").unwrap());
        assert_eq!(tr.gas_limit(), *ARGS.get(&"gas_limit").unwrap());
        assert_eq!(tr.to(), *ARGS.get(&"to").unwrap());
        assert_eq!(tr.value(), *ARGS.get(&"value").unwrap());

        assert_eq!(tr.nonce().len(), 32);
        assert_eq!(tr.gas_price().len(), 32);
        assert_eq!(tr.gas_limit().len(), 32);
        assert_eq!(tr.to().len(), 32);
        assert_eq!(tr.value().len(), 32);
    }

    #[test]
    fn should_encode_transaction() {
        let tr = Transaction::new(&ARGS);
        let tr_encoded: Vec<u8> = tr.into();
        assert_eq!(tr_encoded[0], 0xa0);

        let keys_len = ARGS.keys().len();
        assert_eq!(tr_encoded.len(), keys_len * 32 + keys_len);
    }
}
