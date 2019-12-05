/*
Copyright 2019 ETCDEV GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//! # JSON serialize for hex encoded byte arrays (without '0x' prefix)
/// Macro to generate hex serialazable byte arrays
#[macro_export]
macro_rules! byte_array_struct {
    ($name:ident, $num:expr) => {
        #[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
        ///
        pub struct $name([u8; $num]);

        impl ::std::ops::Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl From<[u8; $num]> for $name {
            fn from(bytes: [u8; $num]) -> Self {
                $name(bytes)
            }
        }

        impl std::convert::TryFrom<Vec<u8>> for $name {
            type Error = ();

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                if value.len() != $num {
                    return Err(());
                }
                let mut result: [u8; $num] = [0; $num];
                result.copy_from_slice(&value);
                Ok(result.into())
            }
        }

        impl Into<[u8; $num]> for $name {
            fn into(self) -> [u8; $num] {
                self.0
            }
        }

        impl $name {
            pub fn into_bytes(self) -> [u8; $num] {
                self.into()
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                use hex::FromHex;
                let v = String::deserialize(deserializer)
                    .and_then(|s| Vec::from_hex(s).map_err(::serde::de::Error::custom))?;

                if v.len() != $num {
                    return Err(::serde::de::Error::custom(&format!(
                        "Byte array invalid length: {}",
                        v.len()
                    )));
                }

                let mut bytes = [0u8; $num];
                bytes.copy_from_slice(&v);

                Ok($name(bytes))
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                use hex;
                serializer.serialize_str(&hex::encode(&self.0))
            }
        }
        //
        //        impl ::rustc_serialize::Decodable for $name {
        //            fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<$name, D::Error> {
        //                use hex::FromHex;
        //                let v = d.read_str()
        //                    .and_then(|s| Vec::from_hex(s).map_err(|e| d.error(&e.to_string())))?;
        //
        //                if v.len() != $num {
        //                    return Err(d.error(&format!("Byte array invalid length: {}", v.len())));
        //                }
        //
        //                let mut bytes = [0u8; $num];
        //
        //                bytes.copy_from_slice(&v);
        //
        //                Ok($name(bytes))
        //            }
        //        }
        //
        //        impl ::rustc_serialize::Encodable for $name {
        //            fn encode<S: ::rustc_serialize::Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        //                s.emit_str(&self.0.to_hex())
        //            }
        //        }
    };
}

#[cfg(test)]
mod tests {
    use crate::tests::*;

    byte_array_struct!(Hex8, 8);

    #[test]
    fn should_encode_default_byte_array() {
        assert_eq!(
            serde_json::to_string(&Hex8::default()).unwrap(),
            "\"0000000000000000\""
        );
    }

    #[test]
    fn should_decode_zero_byte_array() {
        assert_eq!(
            serde_json::from_str::<Hex8>("\"0000000000000000\"").unwrap(),
            Hex8::default()
        );
    }

    #[test]
    fn should_encode_byte_array() {
        let hex = Hex8::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        assert_eq!(serde_json::to_string(&hex).unwrap(), "\"0123456789abcdef\"");
    }

    #[test]
    fn should_decode_byte_array() {
        let hex = Hex8::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        assert_eq!(
            serde_json::from_str::<Hex8>("\"0123456789abcdef\"").unwrap(),
            hex
        );
    }

    #[test]
    fn should_not_decode_invalid_byte_array() {
        assert!(serde_json::from_str::<Hex8>("\"__23456789abcdef\"").is_err());
    }

    #[test]
    fn should_not_decode_insufficient_byte_array() {
        assert!(serde_json::from_str::<Hex8>("1234567890").is_err());
    }

    #[test]
    fn should_not_decode_empty_text() {
        assert!(serde_json::from_str::<Hex8>("\"\"").is_err());
    }

    #[test]
    fn should_not_decode_absent_text() {
        assert!(serde_json::from_str::<Hex8>("").is_err());
    }
}
