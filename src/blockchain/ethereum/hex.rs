/*
Copyright 2022 EmeraldPay, Inc

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
use crate::convert::error::ConversionError;
use crate::error::VaultError;

pub struct EthereumHex {}

///
/// Common utilities to encode and decode bytes in Ethereum-kind hex format (i.e., with 0x prefix)
impl EthereumHex {

    pub fn decode<S: ToString>(s: S) -> Result<Vec<u8>, VaultError> {
        let s = s.to_string();
        let s = if s.starts_with("0x") {
            s.split_at(2).1
        } else {
            return Err(VaultError::ConversionError(ConversionError::InvalidHex))
        };
        hex::decode(s).map_err(|_| VaultError::ConversionError(ConversionError::InvalidHex))
    }

    pub fn encode<T: AsRef<[u8]>>(n: T) -> String {
        format!("0x{}", hex::encode(n))
    }
}

#[cfg(test)]
mod tests {
    use crate::ethereum::hex::EthereumHex;

    #[test]
    fn encode_empty() {
        assert_eq!(
            EthereumHex::encode([]),
            "0x".to_string()
        )
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            EthereumHex::decode("0x").unwrap(),
            Vec::<u8>::new()
        )
    }

    #[test]
    fn encode_single() {
        assert_eq!(
            EthereumHex::encode([1]),
            "0x01".to_string()
        );

        assert_eq!(
            EthereumHex::encode([2]),
            "0x02".to_string()
        );

        assert_eq!(
            EthereumHex::encode([10]),
            "0x0a".to_string()
        );

        assert_eq!(
            EthereumHex::encode([0x80]),
            "0x80".to_string()
        );

        assert_eq!(
            EthereumHex::encode([0xff]),
            "0xff".to_string()
        );
    }

    #[test]
    fn decode_single() {
        assert_eq!(
            EthereumHex::decode("0x01").unwrap(),
            vec![1]
        );
        assert_eq!(
            EthereumHex::decode("0x02").unwrap(),
            vec![2]
        );
        assert_eq!(
            EthereumHex::decode("0x0a").unwrap(),
            vec![10]
        );
        assert_eq!(
            EthereumHex::decode("0x80").unwrap(),
            vec![128]
        );
        assert_eq!(
            EthereumHex::decode("0xff").unwrap(),
            vec![255]
        );
    }

    #[test]
    fn encode_32() {
        assert_eq!(
            EthereumHex::encode(hex::decode("b97b220a0eae07ac7d9dfcdfba252f7d034b0782dd8322664b0c43f4ddcba8c4").unwrap()),
            "0xb97b220a0eae07ac7d9dfcdfba252f7d034b0782dd8322664b0c43f4ddcba8c4".to_string()
        );
    }

    #[test]
    fn decode_32() {
        assert_eq!(
            EthereumHex::decode("0xb97b220a0eae07ac7d9dfcdfba252f7d034b0782dd8322664b0c43f4ddcba8c4").unwrap(),
            hex::decode("b97b220a0eae07ac7d9dfcdfba252f7d034b0782dd8322664b0c43f4ddcba8c4").unwrap()
        );
    }

}
