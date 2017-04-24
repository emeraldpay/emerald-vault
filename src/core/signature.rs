//! # Account ECDSA signatures using the SECG curve secp256k1

use super::Address;
use super::util::to_arr;
use rand::{OsRng, Rng};
use secp256k1::Secp256k1;
use secp256k1::key::{PublicKey, SecretKey};

/// Private key length in bytes
pub const PRIVATE_KEY_BYTES: usize = 32;

/// ECDSA crypto signature length in bytes
pub const ECDSA_SIGNATURE_BYTES: usize = 64;

lazy_static! {
    static ref ECDSA: Secp256k1 = Secp256k1::with_caps(ContextFlag::SignOnly);
}

/// Private key used as x in an ECDSA signature
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivateKey([u8; PRIVATE_KEY_BYTES]);

impl PrivateKey {
    /// Generate a new `PrivateKey` at random (`rand::OsRng`).
    ///
    /// # Example
    ///
    /// ```
    /// assert_eq!(emerald::PrivateKey::gen(), emerald::PrivateKey::gen());
    /// ```
    pub fn gen() -> Self {
        let mut rng = OsRng::new().expect("Expect OS specific random number generator");
        PrivateKey::from(SecretKey::new(&ECDSA, &mut rng))
    }

    /// Try to convert a byte vector to `PrivateKey`.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice with `PRIVATE_KEY_BYTES` length
    ///
    /// # Example
    ///
    /// ```
    /// let pkey = emerald::PrivateKey::try_from(&vec![0u8; emerald::PRIVATE_KEY_BYTES]).unwrap();
    /// assert_eq!(pkey.to_string(),
    ///            "0x0000000000000000000000000000000000000000000000000000000000000000");
    /// ```
    pub fn try_from(data: &[u8]) -> Result<Self, Error> {
        if data.len() != PRIVATE_KEY_BYTES {
            return Err(Error::InvalidLength(data.len()));
        }

        Ok(PrivateKey(to_arr(data)))
    }

    /// Extract `Address` from current private key.
    pub fn to_address(&self) -> Result<Address, Error> {
        let key = PublicKey::from_secret_key(&ECDSA, SecretKey::from(self)?;
        let hash = keccak256(&key.serialize_vec(&ECDSA, false)[1..] /* cut '04' */);
        Address(to_arr(&hash[12..]))
    }

    /// Sign hashed message encoded with bytes
    pub fn sign_data(&self, data: &[u8]) -> Result<[u8; ECDSA_SIGNATURE_BYTES], Error> {
        sign_hash(keccak256(data), pk)
    }

    /// Sign hash from message (Keccak-256)
    pub fn sign_hash(&self, hash: [u8; KECCAK_256]) -> Result<[u8; ECDSA_SIGNATURE_BYTES], Error> {
        let msg = Message::from_slice(&hash)?;
        let key = SecretKey::from_slice(&ECDSA, pk)?;
        let sign = ECDSA.sign_schnorr(&msg, &key)?;

        let mut buf = [0u8; ECDSA_SIGNATURE_BYTES];
        buf.copy_from_slice(&sign.serialize());
        Ok(buf)
    }
}

impl ops::Deref for PrivateKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; PRIVATE_KEY_BYTES]> for PrivateKey {
    fn from(bytes: [u8; PRIVATE_KEY_BYTES]) -> Self {
        PrivateKey(bytes)
    }
}

impl From<SecretKey> for PrivateKey {
    fn from(key: SecretKey) -> Self {
        PrivateKey(to_arr(&key[0..PRIVATE_KEY_BYTES]))
    }
}

impl From<PrivateKey> for SecretKey {
    fn from(key: PrivateKey) -> Self {
        SecretKey::from_slice(&ECDSA, &key).expect("Expect secret key")
    }
}

impl FromStr for PrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err(Error::UnexpectedPrefix(s.to_string()));
        }

        let (_, s) = s.split_at(2);

        s.from_hex().and_then(|v| PrivateKey::try_from(&v))
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", self.0.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::tests::*;

    #[test]
    fn should_sign_hash() {
        let key = PrivateKey::from(
            as_bytes("dcb2652ce3f3e46a57fd4814f926daefd6082c5cda44d35a6fd0f6da67ca256e"));

        assert!(key.sign_hash(
            &as_bytes("1f483adb4a0f8c53d0ff8b6df23bbeae846815e7a52bac234edeaeb082b8d51a")).is_ok());
    }
}
