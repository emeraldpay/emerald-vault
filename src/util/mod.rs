//! # Util functions module

mod crypto;
mod rlp;

pub use self::crypto::{KECCAK256_BYTES, keccak256};
pub use self::rlp::{RLPList, WriteRLP};

/// Convert a slice into array
pub fn to_arr<A, T>(slice: &[T]) -> A
    where A: AsMut<[T]> + Default,
          T: Clone
{
    let mut arr = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut arr).clone_from_slice(slice);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_serialize::hex::FromHex;

    macro_rules! bytes {
        ($hex: expr) => ({
            to_arr(&$hex.from_hex().unwrap())
        })
    }

    #[test]
    fn should_get_bytes_from_string() {
        let arr: [u8; 8] = bytes!("0102030405060708");

        assert_eq!(arr, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }
}
