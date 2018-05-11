//! # JSON serialize format for hex encoded account addresses (without '0x' prefix)

use super::core::Address;
use regex::Regex;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .map(|s| format!("0x{}", s))
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

/// Try to extract `Address` from JSON formatted text
pub fn try_extract_address(text: &str) -> Option<Address> {
    lazy_static! {
        static ref ADDR_RE: Regex = Regex::new(r#"address.+?([a-fA-F0-9]{40})"#).unwrap();
    }

    ADDR_RE
        .captures(text)
        .and_then(|g| g.get(1).map(|m| format!("0x{}", m.as_str())))
        .and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

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

    #[test]
    fn should_extract_address_single_quoted() {
        assert_eq!(
            try_extract_address(r#"address: '008aeeda4d805471df9b2a5b0f38a0c3bcba786b',"#),
            Some(
                "0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b"
                    .parse::<Address>()
                    .unwrap(),
            )
        );
    }

    #[test]
    fn should_extract_address_double_quoted() {
        assert_eq!(
            try_extract_address(r#""address": "0047201aed0b69875b24b614dda0270bcd9f11cc","#),
            Some(
                "0x0047201aed0b69875b24b614dda0270bcd9f11cc"
                    .parse::<Address>()
                    .unwrap(),
            )
        );
    }

    #[test]
    fn should_extract_address_with_optional_fields() {
        assert_eq!(
            try_extract_address(
                r#"  },
                     "address": "3f4e0668c20e100d7c2a27d4b177ac65b2875d26",
                     "meta": "{}",
                     "name": "83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63",
                   }"#,
            ),
            Some(
                "0x3f4e0668c20e100d7c2a27d4b177ac65b2875d26"
                    .parse::<Address>()
                    .unwrap(),
            )
        );
    }

    #[test]
    fn should_ignore_text_without_address() {
        assert_eq!(try_extract_address("\"version\": 3"), None);
    }

    #[test]
    fn should_ignore_empty_text() {
        assert_eq!(try_extract_address(""), None);
    }
}
