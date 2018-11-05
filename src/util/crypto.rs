//! # Crypto util functions

use sha3::Digest;
use sha3::Keccak256;
/// Keccak-256 crypto hash length in bytes
pub const KECCAK256_BYTES: usize = 32;

/// Calculate Keccak-256 crypto hash
pub fn keccak256(data: &[u8]) -> [u8; KECCAK256_BYTES] {
    let mut keccak = Keccak256::default();
    keccak.input(data);
    let mut out = [0u8; KECCAK256_BYTES];
    out.copy_from_slice(&keccak.result()[..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_calculate_empty_keccak256() {
        assert_eq!(
            keccak256(b""),
            to_32bytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",)
        );
    }

    #[test]
    fn should_calculate_small_keccak256() {
        assert_eq!(
            keccak256(b"emerald-rs"),
            to_32bytes("f5ab12ff7b15bb4a5cd3d36a41bdbc8e54c180f7558cc4f8cd40acabda02dd84",)
        );
    }

    #[test]
    fn should_calculate_big_keccak256() {
        assert_eq!(
            keccak256(&[b'-'; 1024]),
            to_32bytes("ea1da5135479c4eb22ed3743c379970895ed2d088fd5d79884b7493aaa49475b",)
        );
    }
}
