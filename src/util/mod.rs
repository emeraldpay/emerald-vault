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
pub use self::tests::*;

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    pub fn to_20bytes(hex: &str) -> [u8; 20] {
        to_arr(&hex.from_hex().unwrap())
    }

    pub fn to_32bytes(hex: &str) -> [u8; 32] {
        to_arr(&hex.from_hex().unwrap())
    }

    #[test]
    fn should_convert_empty_string_into_20bytes() {
        assert_eq!(to_20bytes("0000000000000000000000000000000000000000"),
                   [0u8; 20]);
    }

    #[test]
    fn should_convert_key_into_32bytes() {
        assert_eq!(to_32bytes("fa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f"),
                   [0xfa, 0x38, 0x4e, 0x6f, 0xe9, 0x15, 0x74, 0x7c, 0xd1, 0x3f, 0xaa, 0x10, 0x22,
                    0x04, 0x4b, 0x0d, 0xef, 0x5e, 0x6b, 0xec, 0x42, 0x38, 0xbe, 0xc5, 0x31, 0x66,
                    0x48, 0x7a, 0x5c, 0xca, 0x56, 0x9f]);
    }
}
