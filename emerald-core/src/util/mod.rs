//! # Util functions module
mod crypto;
mod rlp;

pub use self::crypto::{KECCAK256_BYTES, keccak256};
pub use self::rlp::{RLPList, WriteRLP};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::Utc;
use std::io::Cursor;
use std::mem::transmute;

static HEX_CHARS: &'static [u8] = b"0123456789abcdef";

/// Convert `self` into hex string
pub trait ToHex {
    /// converts to hex
    fn to_hex(&self) -> String;
}

impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        let mut v = Vec::with_capacity(self.len() * 2);
        for &byte in self.iter() {
            v.push(HEX_CHARS[(byte >> 4) as usize]);
            v.push(HEX_CHARS[(byte & 0xf) as usize]);
        }

        unsafe { String::from_utf8_unchecked(v) }
    }
}

impl ToHex for u64 {
    fn to_hex(&self) -> String {
        let bytes: [u8; 8] = unsafe { transmute(self.to_be()) };
        bytes.to_hex()
    }
}

/// Convert byte array into `u64`
///
/// # Arguments
///
/// * `v` - array to be converted
///
pub fn to_u64(v: &[u8]) -> u64 {
    let data = align_bytes(v, 8);
    let mut buf = Cursor::new(&data);

    buf.read_u64::<BigEndian>().unwrap()
}

/// Trix hex prefix `0x`
///
/// # Arguments
///
/// * `val` - string to be trimmed
///
pub fn trim_hex(val: &str) -> &str {
    if !val.starts_with("0x") {
        return val;
    }

    let (_, s) = val.split_at(2);
    s
}



/// Convert a slice into array
///
/// # Arguments
///
/// * `slice` - slice to be converted
///
pub fn to_arr<A, T>(slice: &[T]) -> A
where
    A: AsMut<[T]> + Default,
    T: Clone,
{
    let mut arr = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut arr).clone_from_slice(slice);
    arr
}

/// Padding high bytes with `O` to fit `len` bytes
///
/// # Arguments
///
/// * `data` - data to be aligned
/// * `len` - length of required array
///
pub fn align_bytes(data: &[u8], len: usize) -> Vec<u8> {
    if data.len() >= len {
        return data.to_vec();
    }

    let mut v = vec![0u8; len - data.len()];
    v.extend_from_slice(data);
    v
}

/// Padding hex string with `O` to get even length
///
/// # Arguments
///
/// * `data` - data to be aligned
///
pub fn to_even_str(data: &str) -> String {
    if data.len() % 2 == 0 {
        return String::from(data);
    }

    let mut v = String::from("0");
    v.push_str(data);
    v
}

/// Trim all high zero bytes
///
/// # Arguments
///
/// * `data` - value to be trimmed
///
pub fn trim_bytes(data: &[u8]) -> &[u8] {
    let mut n = 0;
    for b in data {
        if *b != 0u8 {
            break;
        }
        n += 1;
    }
    &data[n..data.len()]
}

/// Counts bytes required to hold `x` value
///
/// # Arguments
///
/// * `x` - value to find size
///
pub fn bytes_count(x: usize) -> u8 {
    match x {
        _ if x > 0xff => 1 + bytes_count(x >> 8),
        _ if x > 0 => 1,
        _ => 0,
    }
}

/// Converts `unsigned` value to byte array
///
/// # Arguments
///
/// * `x` - a value to be converted into byte vector
/// * `len` - size of value
///
pub fn to_bytes(x: u64, len: u8) -> Vec<u8> {
    let mut buf = vec![];
    match len {
        1 => buf.push(x as u8),
        2 => buf.write_u16::<BigEndian>(x as u16).unwrap(),
        4 => buf.write_u32::<BigEndian>(x as u32).unwrap(),
        8 => buf.write_u64::<BigEndian>(x).unwrap(),
        _ => (),
    }
    buf
}

/// Time stamp in format `yyy-mm-ddThh-mm-ss`
pub fn timestamp() -> String {
    // `2017-05-01T20:21:10.163281100+00:00` -> `2017-05-01T20-21-10`
    str::replace(&Utc::now().to_rfc3339(), ":", "-")
        .split('.')
        .next()
        .unwrap()
        .to_string()
}

#[cfg(test)]
pub use self::tests::*;

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_serialize::hex::FromHex;
    use tests::*;

    pub fn to_16bytes(hex: &str) -> [u8; 16] {
        to_arr(&hex.from_hex().unwrap())
    }

    pub fn to_20bytes(hex: &str) -> [u8; 20] {
        to_arr(&hex.from_hex().unwrap())
    }

    pub fn to_32bytes(hex: &str) -> [u8; 32] {
        to_arr(&hex.from_hex().unwrap())
    }

    #[test]
    fn should_convert_zero_string_into_16bytes() {
        assert_eq!(to_16bytes("00000000000000000000000000000000"), [0u8; 16]);
    }

    #[test]
    fn should_convert_address_into_20bytes() {
        assert_eq!(
            to_20bytes("3f4e0668c20e100d7c2a27d4b177ac65b2875d26"),
            [
                0x3f,
                0x4e,
                0x06,
                0x68,
                0xc2,
                0x0e,
                0x10,
                0x0d,
                0x7c,
                0x2a,
                0x27,
                0xd4,
                0xb1,
                0x77,
                0xac,
                0x65,
                0xb2,
                0x87,
                0x5d,
                0x26,
            ]
        );
    }

    #[test]
    fn should_convert_key_into_32bytes() {
        assert_eq!(
            to_32bytes(
                "fa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f",
            ),
            [
                0xfa,
                0x38,
                0x4e,
                0x6f,
                0xe9,
                0x15,
                0x74,
                0x7c,
                0xd1,
                0x3f,
                0xaa,
                0x10,
                0x22,
                0x04,
                0x4b,
                0x0d,
                0xef,
                0x5e,
                0x6b,
                0xec,
                0x42,
                0x38,
                0xbe,
                0xc5,
                0x31,
                0x66,
                0x48,
                0x7a,
                0x5c,
                0xca,
                0x56,
                0x9f,
            ]
        );
    }

    #[test]
    fn should_align_empty_bytes() {
        assert_eq!(align_bytes(&[], 8), vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn should_align_some_zero_bytes() {
        assert_eq!(align_bytes(&[0, 0, 0], 8), vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn should_align_all_zero_bytes() {
        assert_eq!(
            align_bytes(&[0, 0, 0, 0, 0, 0, 0, 0], 8),
            vec![0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn should_align_some_bytes() {
        assert_eq!(align_bytes(&[0, 1, 2, 3], 8), vec![0, 0, 0, 0, 0, 1, 2, 3]);
    }

    #[test]
    fn should_align_full_bytes() {
        assert_eq!(
            align_bytes(&[1, 2, 3, 4, 5, 6, 7, 8], 8),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn should_skip_smaller_length() {
        assert_eq!(
            align_bytes(&[1, 2, 3, 4, 5, 6, 7, 8], 6),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn should_align_to_even_str() {
        assert_eq!(to_even_str("100"), String::from("0100"));
    }

    #[test]
    fn should_skip_already_even_str() {
        assert_eq!(to_even_str("100012"), String::from("100012"));
    }

    #[test]
    fn should_trim_empty_bytes() {
        assert_eq!(trim_bytes(&[]), &[] as &[u8]);
    }

    #[test]
    fn should_trim_zero_bytes() {
        assert_eq!(trim_bytes(&[0, 0, 0]), &[] as &[u8]);
    }

    #[test]
    fn should_trim_some_bytes() {
        assert_eq!(trim_bytes(&[0, 0, 0, 0, 0, 1, 2, 3]), &[1, 2, 3]);
    }

    #[test]
    fn should_trim_hex_prefix() {
        assert_eq!("12345", trim_hex("0x12345"))
    }

    #[test]
    fn should_skip_trim_hex_prefix() {
        assert_eq!("12345", trim_hex("12345"))
    }

    #[test]
    fn should_count_bytes_for_rlp() {
        assert_eq!(bytes_count(0x00), 0);
        assert_eq!(bytes_count(0x01), 1);
        assert_eq!(bytes_count(0xff), 1);
        assert_eq!(bytes_count(0xff01), 2);
        assert_eq!(bytes_count(0xffff01), 3);

    }

    #[test]
    fn should_convert_u8_to_bytes() {
        assert_eq!([1], to_bytes(1, 1).as_slice());
        assert_eq!([2], to_bytes(2, 1).as_slice());
        assert_eq!([127], to_bytes(127, 1).as_slice());
        assert_eq!([128], to_bytes(128, 1).as_slice());
        assert_eq!([255], to_bytes(255, 1).as_slice());
    }

    #[test]
    fn should_convert_u16_to_bytes() {
        assert_eq!([0, 1], to_bytes(1, 2).as_slice());
        assert_eq!([0, 2], to_bytes(2, 2).as_slice());
        assert_eq!([0, 255], to_bytes(255, 2).as_slice());
        assert_eq!([1, 0], to_bytes(256, 2).as_slice());
        assert_eq!([0x12, 0x34], to_bytes(0x1234, 2).as_slice());
        assert_eq!([0xff, 0xff], to_bytes(0xffff, 2).as_slice());
    }

    #[test]
    fn should_convert_u32_to_bytes() {
        assert_eq!([0, 0, 0, 1], to_bytes(1, 4).as_slice());
        assert_eq!([0x12, 0x34, 0x56, 0x78], to_bytes(0x12345678, 4).as_slice());
        assert_eq!([0xff, 0x0, 0x0, 0x0], to_bytes(0xff000000, 4).as_slice());
        assert_eq!([0x00, 0xff, 0x0, 0x0], to_bytes(0x00ff0000, 4).as_slice());
    }

    #[test]
    fn should_convert_u64_to_bytes() {
        assert_eq!([0, 0, 0, 0, 0, 0, 0, 1], to_bytes(1, 8).as_slice());
        assert_eq!(
            [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef],
            to_bytes(0x1234567890abcdef, 8).as_slice()
        );
        assert_eq!(
            [0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            to_bytes(0xff00000000000000, 8).as_slice()
        );
        assert_eq!(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            to_bytes(0xffffffffffffffff, 8).as_slice()
        );
    }

    #[test]
    fn should_generate_timestamp() {
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}[T]\d{2}-\d{2}-\d{2}").unwrap();

        assert!(re.is_match(&timestamp()));
    }
}
