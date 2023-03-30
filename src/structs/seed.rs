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
use crate::structs::crypto::GlobalKey;
use crate::structs::types::UsesOddKey;

byte_array_struct!(
    pub struct Bytes256(32);
);

const NONE_SEED_KEY: &str = "NONE";

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

    ///
    /// Ecnryption key used to encrypt test seed created with #create_raw()
    pub fn nokey() -> String {
        return NONE_SEED_KEY.to_string()
    }


    ///
    /// Create a Seed Source from the specified seed. Encrypt it using the global key
    pub fn create(seed: Vec<u8>, global_password: &[u8], global: GlobalKey) -> Result<Self, CryptoError> {
        let value = Encrypted::encrypt(seed, global_password, Some(global))?;
        Ok(SeedSource::Bytes(value))
    }

    ///
    /// Create Seed Source that is supposed to be used in-memory. Ex. to check addresses, etc.
    /// It doesn't use a Global Key and should not be saved in this form.
    /// The encryption password is always `NONE` (use #nokey() to get it)
    ///
    /// ```
    /// use emerald_vault::mnemonic::{Mnemonic, Language};
    /// use emerald_vault::structs::seed::SeedSource;
    /// use hdpath::StandardHDPath;
    /// # use std::str::FromStr;
    ///
    /// let phrase = Mnemonic::try_from(
    ///     Language::English,
    ///     "quote ivory blast onion below kangaroo tonight spread awkward decide farm gun exact wood brown",
    /// ).unwrap();
    /// let seed = SeedSource::create_raw(phrase.seed(None)).unwrap();
    /// let _ = seed.get_pk(
    ///     // use _nokey_ to decrypt the seed
    ///     Some(SeedSource::nokey()),
    ///     // Global Key is not used, threfore None
    ///     &None,
    ///     // ....
    ///     &StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()
    /// );
    /// ```
    pub fn create_raw(seed: Vec<u8>) -> Result<Self, CryptoError> {
        let value = Encrypted::encrypt(seed, NONE_SEED_KEY.as_bytes(), None)?;
        Ok(SeedSource::Bytes(value))
    }

    pub(crate) fn reencrypt(self, password: &[u8], global_password: &[u8], global: GlobalKey) -> Result<Self, CryptoError> {
        match self {
            SeedSource::Ledger(_) => Err(CryptoError::UnsupportedSource("Ledger".to_string())),
            SeedSource::Bytes(e) => Ok(
                SeedSource::Bytes(e.reencrypt(Some(password), global_password, global)?)
            )
        }
    }
}

impl UsesOddKey for SeedSource {
    fn is_odd_key(&self) -> bool {
        match self {
            SeedSource::Ledger(_) => false,
            SeedSource::Bytes(e) => e.is_odd_key()
        }
    }
}

impl UsesOddKey for Seed {
    fn is_odd_key(&self) -> bool {
        self.source.is_odd_key()
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

impl Default for Seed {
    /// Note that the _default_ value must be used to fill missing fields and should never use it as is, because the default seed key is empty
    fn default() -> Self {
        Seed {
            id: Uuid::new_v4(),
            source: SeedSource::Bytes(
                // empty key because it should never be used in real situation
                Encrypted::encrypt(vec![], "NONE".as_bytes(), None).unwrap()
            ),
            label: None,
            created_at: Utc::now(),
        }
    }
}

ord_by_date_id!(Seed);

impl Default for LedgerSource {
    fn default() -> Self {
        LedgerSource { fingerprints: vec![] }
    }
}

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
