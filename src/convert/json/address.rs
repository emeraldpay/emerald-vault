use crate::Address;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .map(|s| {
                if s.starts_with("0x") {
                    s
                } else {
                    format!("0x{}", s)
                }
            })
            .and_then(|s| Address::from_str(&s).map_err(de::Error::custom))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string()[2..]) /* cut '0x' prefix */
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::*;

    #[test]
    fn should_encode_default_address() {
        assert_eq!(
            serde_json::to_string(&Address::default()).unwrap(),
            "\"0000000000000000000000000000000000000000\""
        );
    }

    #[test]
    fn should_decode_zero_address() {
        assert_eq!(
            serde_json::from_str::<Address>("\"0000000000000000000000000000000000000000\"")
                .unwrap(),
            Address::default()
        );
    }

    #[test]
    fn should_encode_real_address() {
        let addr = Address([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            serde_json::to_string(&addr).unwrap(),
            "\"0e7c045110b8dbf29765047380898919c5cb56f4\""
        );
    }

    #[test]
    fn should_decode_real_address() {
        let addr = Address([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            serde_json::from_str::<Address>("\"0e7c045110b8dbf29765047380898919c5cb56f4\"")
                .unwrap(),
            addr
        );
    }

    #[test]
    fn should_not_decode_wrong_address() {
        assert!(
            serde_json::from_str::<Address>("\"__7c045110b8dbf29765047380898919c5cb56f4\"")
                .is_err()
        );
    }

    #[test]
    fn should_not_decode_not_string_address() {
        assert!(serde_json::from_str::<Address>("1234567890").is_err());
    }

    #[test]
    fn should_not_decode_empty_address() {
        assert!(serde_json::from_str::<Address>("\"\"").is_err());
    }

    #[test]
    fn should_not_decode_absent_address() {
        assert!(serde_json::from_str::<Address>("").is_err());
    }
}
