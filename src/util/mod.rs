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
pub mod tests {
    use super::*;
    use rustc_serialize::hex::FromHex;

    pub fn to_20bytes(hex: &str) -> [u8; 20] {
        to_arr(&hex.from_hex().unwrap())
    }

    pub fn to_32bytes(hex: &str) -> [u8; 32] {
        to_arr(&hex.from_hex().unwrap())
    }

    #[test]
    fn should_get_bytes_from_string() {
        assert_eq!(to_20bytes("0000000000000000000000000000000000000000"),
                   [0u8; 20]);
    }
}
