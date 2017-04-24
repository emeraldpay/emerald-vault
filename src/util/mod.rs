//! # Util functions module

mod crypto;
mod rlp;

pub use self::crypto::{KECCAK256_BYTES, keccak256};
pub use self::rlp::RLPList;

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
    pub use super::*;
    pub use super::tests::*;
    use rustc_serialize::hex::FromHex;

    /// Convert a string encoded string into array
    pub fn as_bytes(hex: &str) -> A
        where A: Box<[u8]>
    {
        to_arr(hex.from_hex().unwrap())
    }
}
