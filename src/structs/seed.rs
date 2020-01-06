use uuid::Uuid;
use crate::structs::crypto::Encrypted;
use crate::Address;
use sha2::Digest;
use std::convert::TryFrom;
use crate::structs::types::HasUuid;
use crate::crypto::error::CryptoError;

byte_array_struct!(Bytes256, 32);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Seed {
    pub id: Uuid,
    pub source: SeedSource
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SeedSource {
    Bytes(Encrypted),
    Ledger(LedgerSource)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LedgerSource {
    pub fingerprints: Vec<HDPathFingerprint>
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HDPathFingerprint {
    pub hd_path: String,
    pub value: FingerprintType
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FingerprintType {
    AddressSha256(Bytes256)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SeedRef {
    pub seed_id: Uuid,
    pub hd_path: String
}

impl HDPathFingerprint {
    pub fn from_address(hd_path: String, address: &Address) -> HDPathFingerprint {
        let hash = sha2::Sha256::digest(address);
        let f = Bytes256::try_from(hash.as_slice()).unwrap();
        HDPathFingerprint {
            hd_path,
            value: FingerprintType::AddressSha256(f)
        }
    }
}

impl HasUuid for Seed {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl SeedSource {
    pub fn create_bytes(seed: Vec<u8>, password: &str) -> Result<Self, CryptoError> {
        let value = Encrypted::encrypt(seed, password)?;
        Ok(SeedSource::Bytes(value))
    }
}
