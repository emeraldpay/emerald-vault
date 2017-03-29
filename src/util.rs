/// Encoder for RLP compression.
pub struct RlpEncoder;

impl RlpEncoder {
    /// Compressing of simple values.
    pub fn encode_raw_bytes (data: &[u8]) -> Vec<u8> {
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
                let len_bytes = len.to_bytes();
                out.push(0xb7 + len_bytes.len() as u8);
                out.extend(len_bytes.iter().cloned());
                out.extend(data.iter().cloned());
            }
        }

        out
    }

    /// Compressing single item of container.
    pub fn encode_nested_bytes (data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        match data.len() {
            len @ 0...55 => {
                out.push(0xc0 + len as u8);
                out.extend(data.iter().cloned());
            }
            len @ _ => {
                let len_bytes = len.to_bytes();

                out.push(0xf7 + len_bytes.len() as u8);
                out.extend(len_bytes.iter().cloned());
                out.extend(data.iter().cloned());
            }
        }

        out
    }
}

/// Converters item to binary form.
pub trait ToBytes<T> {
    fn to_bytes(&self) -> T;
}

impl ToBytes<Vec<u8>> for usize {
    fn to_bytes(&self) -> Vec<u8> {
        let val = *self as u32;
        let len = 4 - val.leading_zeros() / 8;
        let mut out = vec!();

        for i in 1..len+1 {
            let j = len - i;
            out.push((*self >> (j * 8)) as u8);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn should_rlp_nested() {
        let data = vec![0x00];
        let compressed = vec![0xc1, 0x00];
        assert_eq!(compressed, RlpEncoder::encode_nested_bytes(&data));

        let mut data = vec!();
        let mut compressed = vec![0xf7];
        for i in 0..55 {
            data.push(i as u8);
            compressed.push(i as u8);
        }
        assert_eq!(compressed, RlpEncoder::encode_nested_bytes(&data));

        let mut data = vec!();
        let mut compressed = vec![0xf9, 0x04, 0x00];
        for i in 0..1024 {
            data.push(i as u8);
            compressed.push(i as u8);
        }
        assert_eq!(compressed, RlpEncoder::encode_nested_bytes(&data));
    }
}
