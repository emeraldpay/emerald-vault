use crate::{
    crypto::error::CryptoError,
    structs::{crypto::Encrypted, types::HasUuid},
    EthereumAddress,
};
use chrono::{DateTime, Utc};
use hdpath::StandardHDPath;
use sha2::Digest;
use std::convert::TryFrom;
use uuid::Uuid;

byte_array_struct!(
    pub struct Bytes256(32);
);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Seed {
    pub id: Uuid,
    pub source: SeedSource,
    pub label: Option<String>,
    ///creation date of the seed
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SeedSource {
    Bytes(Encrypted),
    Ledger(LedgerSource),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LedgerSource {
    pub fingerprints: Vec<HDPathFingerprint>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HDPathFingerprint {
    pub hd_path: StandardHDPath,
    pub value: FingerprintType,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FingerprintType {
    AddressSha256(Bytes256),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SeedRef {
    pub seed_id: Uuid,
    pub hd_path: StandardHDPath,
}

impl HDPathFingerprint {
    pub fn from_address(hd_path: StandardHDPath, address: &EthereumAddress) -> HDPathFingerprint {
        let hash = sha2::Sha256::digest(address);
        let f = Bytes256::try_from(hash.as_slice()).unwrap();
        HDPathFingerprint {
            hd_path,
            value: FingerprintType::AddressSha256(f),
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

impl SeedRef {
    /// extract Account from HDPath if it's structured as BIP-44. (m/purpose'/coin_type'/account'/change/address_index)
    /// To do so the HDPath must be valid and starts with 3 hardened values (purpose'/coin_type'/account'),
    /// otherwise the method returns Err
    pub fn get_account_id(&self) -> Result<u32, ()> {
        Ok(self.hd_path.account())
    }
}

ord_by_date_id!(Seed);

#[cfg(test)]
mod tests {
    use crate::structs::seed::SeedRef;
    use hdpath::StandardHDPath;
    use std::convert::TryFrom;

    #[test]
    fn account_id_for_standard_hdpath() {
        let seed = SeedRef {
            seed_id: Default::default(),
            hd_path: StandardHDPath::try_from("m/44'/0'/0'/0/0").unwrap(),
        };
        assert_eq!(Ok(0), seed.get_account_id());

        let seed = SeedRef {
            seed_id: Default::default(),
            hd_path: StandardHDPath::try_from("m/44'/60'/0'/0/0").unwrap(),
        };
        assert_eq!(Ok(0), seed.get_account_id());

        let seed = SeedRef {
            seed_id: Default::default(),
            hd_path: StandardHDPath::try_from("m/44'/60'/3'/0/0").unwrap(),
        };
        assert_eq!(Ok(3), seed.get_account_id());

        let seed = SeedRef {
            seed_id: Default::default(),
            hd_path: StandardHDPath::try_from("m/44'/0'/1234'/0/0").unwrap(),
        };
        assert_eq!(Ok(1234), seed.get_account_id());
    }
}
