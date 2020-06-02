use crate::crypto::error::CryptoError;
use crate::hdwallet::bip32::HDPath;
use crate::structs::crypto::Encrypted;
use crate::structs::types::HasUuid;
use crate::Address;
use bitcoin::util::bip32::ChildNumber;
use hdpath::StandardHDPath;
use sha2::Digest;
use std::convert::TryFrom;
use uuid::Uuid;

byte_array_struct!(Bytes256, 32);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Seed {
    pub id: Uuid,
    pub source: SeedSource,
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
    pub fn from_address(hd_path: StandardHDPath, address: &Address) -> HDPathFingerprint {
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
    /// parse current HDPath
    pub fn parsed_hd_path(&self) -> Result<HDPath, ()> {
        HDPath::try_from(self.hd_path.to_string().as_str()).map_err(|_| ())
    }

    /// extract Account from HDPath if it's structured as BIP-44. (m/purpose'/coin_type'/account'/change/address_index)
    /// To do so the HDPath must be valid and starts with 3 hardened values (purpose'/coin_type'/account'),
    /// otherwise the method returns Err
    pub fn get_account_id(&self) -> Result<u32, ()> {
        if let Ok(path) = self.parsed_hd_path() {
            //for BIP44 == m/purpose'/coin_type'/account'/change/address_index
            if path.len() > 2
                && path[0].is_hardened()
                && path[1].is_hardened()
                && path[2].is_hardened()
            {
                if let ChildNumber::Hardened { index: n } = path[2] {
                    return Ok(n);
                }
            }
        }
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use crate::hdwallet::bip32::HDPath;
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
