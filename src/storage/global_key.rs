use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};
use protobuf::Message;
use uuid::Uuid;
use crate::error::VaultError;
use crate::storage::vault::{safe_update, VaultStorage};
use crate::structs::crypto::{Encrypted, GlobalKey, GlobalKeyRef};
use crate::proto::crypto::{GlobalKey as proto_GlobalKey};
use crate::structs::types::UsesOddKey;

///
/// Manage storage for a Global Key
pub struct VaultGlobalKey {
    pub(crate) vault: PathBuf,
}

pub(crate) const KEY_FILE: &'static str = "global.key";

impl VaultGlobalKey {
    fn get_path(&self) -> PathBuf {
        self.vault.join(KEY_FILE)
    }

    ///
    /// Check if Global Key is set for current Vault.
    pub fn is_set(&self) -> bool {
        self.get_path().is_file()
    }

    ///
    /// Create new Global Key for the current vault. Can be created only once.
    /// The key itself is randomly generated and encrypted with the provided password.
    ///
    /// * `password` - password to encrypt global key
    pub fn create(&self, password: &str) -> Result<(), VaultError> {
        if self.is_set() {
            return Err(VaultError::FilesystemError("Global key already set".to_string()))
        }
        let global = GlobalKey::generate(password.as_bytes())?;
        let encoded: Vec<u8> = proto_GlobalKey::try_from(&global).unwrap().write_to_bytes()?;
        let file = self.get_path();
        let write_result = fs::write(&file, encoded);
        if write_result.is_err() {
            // if we did actually wrote to the file, maybe partially, but still got an error then we
            // need to do a clean up and remove the corrupted file
            if file.exists() && fs::remove_file(&file).is_err() {
                println!("Failed to remove {:?}", file)
            }
            return Err(VaultError::FilesystemError(
                format!("Failed to write global key: {:?}", write_result.err().unwrap()))
            );
        }
        return Ok(())
    }

    ///
    /// Get current global key if it's set
    pub fn get(&self) -> Result<GlobalKey, VaultError> {
        let file = self.get_path();
        if file.exists() && file.is_file() {
            let proto = fs::read(file)?;
            let global = GlobalKey::try_from(proto.as_slice())?;
            return Ok(global)
        }
        Err(VaultError::FilesystemError("Global key doesn't exist".to_string()))
    }

    ///
    /// Try to a Global Key. Returns None if it's not set, or Error when there is an error to access it (ex. IO Error, etc)
    pub fn get_if_exists(&self) -> Result<Option<GlobalKey>, VaultError> {
        if !self.is_set() {
            return Ok(None)
        }
        // may fail to read/decode and return just a Err(VaultError)
        let global = self.get()?;
        Ok(Some(global))
    }

    ///
    /// Change password for the global key.
    /// Note that it doesn't change the actual secret value which used to derive keys for dependent objects
    pub fn change_password(self, current_password: &str, new_password: &str) -> Result<(), VaultError> {
        if !self.is_set() {
            return Err(VaultError::GlobalKeyRequired)
        }

        let mut g = self.get()?;
        let key_value = g.key.decrypt(current_password.as_bytes(), None)?;
        g.key = Encrypted::encrypt(key_value, new_password.as_bytes(), None)?;

        let encoded: Vec<u8> = proto_GlobalKey::try_from(&g).unwrap().write_to_bytes()?;
        // NOTE it doesn't make a copy of the old key in archive, because if the reason to change
        // password is that the previous one is unsecure the copy make the change completely bogus
        safe_update(self.get_path(), encoded, None)
    }

    ///
    /// Verify that password can decrypt the Global Key.
    /// May return Err if the Global Key is not set, or IO/conversion/etc errors while reading it
    pub fn verify_password(self, password: &str) -> Result<bool, VaultError> {
        if !self.is_set() {
            return Err(VaultError::GlobalKeyRequired)
        }

        let mut g = self.get()?;
        g.key.decrypt(password.as_bytes(), None)
            .map_or(Ok(false), |_| Ok(true))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LegacyEntryRef {
    Seed(Uuid),
    PrivateKey(Uuid)
}

impl VaultStorage {
    ///
    /// Get list of items in the Vault that use individual passwords. Such item may be a Seed or an individual Key
    pub fn get_global_key_missing(&self) -> Result<Vec<LegacyEntryRef>, VaultError> {
        let seeds: Vec<LegacyEntryRef> = self.seeds()
            .list_entries()?
            .iter()
            .filter(|seed| seed.is_odd_key())
            .map(|seed| LegacyEntryRef::Seed(seed.id))
            .collect();
        let keys: Vec<LegacyEntryRef> = self.keys()
            .list_entries()?
            .iter()
            .filter(|key| key.is_odd_key())
            .map(|key| LegacyEntryRef::PrivateKey(key.id))
            .collect();

        let mut result = Vec::with_capacity(seeds.len() + keys.len());
        result.extend(seeds);
        result.extend(keys);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use hdpath::StandardHDPath;
    use tempdir::TempDir;
    use crate::chains::Blockchain;
    use crate::EthereumAddress;
    use crate::storage::vault::VaultStorage;
    use crate::structs::pk::PrivateKeyHolder;
    use crate::structs::seed::{Seed, SeedSource, LedgerSource};
    use crate::storage::global_key::LegacyEntryRef;

    #[test]
    fn create_when_unset() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global = vault.global_key();
        assert!(!global.is_set());
        global.create("test").expect("create global key");
        assert!(global.is_set());
    }

    #[test]
    fn cannot_get_when_unset() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global = vault.global_key();
        assert!(!global.is_set());
        let value_result = global.get();
        assert!(value_result.is_err());
    }

    #[test]
    fn cannot_create_when_set() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global = vault.global_key();
        assert!(!global.is_set());
        global.create("test-1").expect("create global key");
        assert!(global.is_set());
        let global_value_1 = global.get().unwrap();

        let create2 = global.create("test-2");
        assert!(create2.is_err());

        let global_value_2 = global.get().unwrap();
        assert_eq!(global_value_1, global_value_2);
    }

    #[test]
    fn returns_when_exists() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global = vault.global_key();
        global.create("test-1").unwrap();

        let value = global.get_if_exists();

        assert!(value.is_ok());
        assert!(value.unwrap().is_some());
    }

    #[test]
    fn verify_correct() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global = vault.global_key();
        global.create("test-1").unwrap();

        let value = global.verify_password("test-1");

        assert!(value.is_ok());
        assert!(value.unwrap());
    }

    #[test]
    fn verify_wrong() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global = vault.global_key();
        global.create("test-1").unwrap();

        let value = global.verify_password("test-2");

        assert!(value.is_ok());
        assert!(!value.unwrap());
    }

    #[test]
    fn none_when_doesnt_exist() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global = vault.global_key();

        let value = global.get_if_exists();

        assert!(value.is_ok());
        assert!(value.unwrap().is_none());
    }

    #[test]
    fn is_used_in_encryption() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global_store = vault.global_key();
        global_store.create("test-1").unwrap();
        let global = Some(global_store.get().unwrap());

        let seed_id = vault.seeds().add(
            Seed::test_generate(None, "test-1".as_bytes(), global.clone()).unwrap()
        ).unwrap();

        let seed_source = vault.seeds().get(seed_id).unwrap().source;

        let get_no_global = seed_source.get_addresses::<EthereumAddress>(
            Some("test-1".to_string()),
            None,
            &vec![StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()],
            Blockchain::Ethereum,
        );

        assert!(get_no_global.is_err());

        let get_w_global = seed_source.get_addresses::<EthereumAddress>(
            Some("test-1".to_string()),
            global,
            &vec![StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()],
            Blockchain::Ethereum,
        );

        println!("Result: {:?}", get_w_global);

        assert!(get_w_global.is_ok());
    }

    #[test]
    fn can_change_password() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global_store = vault.global_key();
        global_store.create("test-1").unwrap();
        let global = Some(global_store.get().unwrap());

        let seed_id = vault.seeds().add(
            Seed::test_generate(None, "test-1".as_bytes(), global.clone()).unwrap()
        ).unwrap();

        let changed = global_store.change_password("test-1", "test-2");
        assert!(changed.is_ok());

        // don't forget to read it from disk
        let global = Some(vault.global_key().get().unwrap());

        let seed_source = vault.seeds().get(seed_id).unwrap().source;

        let get_old_password = seed_source.get_addresses::<EthereumAddress>(
            Some("test-1".to_string()),
            global.clone(),
            &vec![StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()],
            Blockchain::Ethereum,
        );
        assert!(get_old_password.is_err());

        let get_new_password = seed_source.get_addresses::<EthereumAddress>(
            Some("test-2".to_string()),
            global,
            &vec![StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()],
            Blockchain::Ethereum,
        );

        println!("Result: {:?}", get_new_password);

        assert!(get_new_password.is_ok());
    }

    #[test]
    fn doesnt_change_wrong_password() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global_store = vault.global_key();
        global_store.create("test-1").unwrap();
        let global = Some(global_store.get().unwrap());

        let seed_id = vault.seeds().add(
            Seed::test_generate(None, "test-1".as_bytes(), global.clone()).unwrap()
        ).unwrap();

        let changed = global_store.change_password("test-1-wrong", "test-2");
        assert!(changed.is_err());

        // don't forget to read it from disk
        let global = Some(vault.global_key().get().unwrap());

        let seed_source = vault.seeds().get(seed_id).unwrap().source;

        let get_old_password = seed_source.get_addresses::<EthereumAddress>(
            Some("test-1".to_string()),
            global.clone(),
            &vec![StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()],
            Blockchain::Ethereum,
        );
        assert!(get_old_password.is_ok());

        let get_new_password = seed_source.get_addresses::<EthereumAddress>(
            Some("test-2".to_string()),
            global,
            &vec![StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()],
            Blockchain::Ethereum,
        );

        assert!(get_new_password.is_err());
    }

    #[test]
    fn ignored_for_legacy_seed() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed_id = vault.seeds().add(
            Seed::test_generate(None, "test-1".as_bytes(), None).unwrap()
        ).unwrap();

        let global_store = vault.global_key();
        global_store.create("test-1").unwrap();
        let global = Some(global_store.get().unwrap());

        let seed_source = vault.seeds().get(seed_id).unwrap().source;

        // because seed was created without global key it can be decrypted with or without it

        let get_no_global = seed_source.get_addresses::<EthereumAddress>(
            Some("test-1".to_string()),
            None,
            &vec![StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()],
            Blockchain::Ethereum,
        );

        assert!(get_no_global.is_ok());

        let get_w_global = seed_source.get_addresses::<EthereumAddress>(
            Some("test-1".to_string()),
            global,
            &vec![StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()],
            Blockchain::Ethereum,
        );

        println!("Result: {:?}", get_w_global);

        assert!(get_w_global.is_ok());
    }

    #[test]
    fn reports_nokey_items() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed_id_1 = vault.seeds().add(
            Seed::test_generate(None, "test-1".as_bytes(), None).unwrap()
        ).unwrap();

        let key_id_1 = vault.keys().add(
            PrivateKeyHolder::generate_ethereum_raw("test-2").unwrap()
        ).unwrap();

        println!("init: {:?}, {:?}", seed_id_1, key_id_1);

        let global_store = vault.global_key();
        global_store.create("test-g").unwrap();
        let global = Some(global_store.get().unwrap());

        let seed_id_2 = vault.seeds().add(
            Seed::test_generate(None, "test-g".as_bytes(), global.clone()).unwrap()
        ).unwrap();

        let key_id_2 = vault.keys().add(
            PrivateKeyHolder::create_ethereum_raw(hex::decode("15cc67bb2a7f75a682198264728b951c461bd4a92692ab3bb00f01e9dbe2fbe4").unwrap(), "test-g", global.clone()).unwrap()
        ).unwrap();

        let key_id_3 = vault.keys().add(
            PrivateKeyHolder::generate_ethereum_raw("test-3").unwrap()
        ).unwrap();

        println!("post: {:?}, {:?}, {:?}", seed_id_2, key_id_2, key_id_3);

        let unused = vault.get_global_key_missing().unwrap();

        println!("{:?}", unused);

        assert_eq!(unused.len(), 3);

        assert!(unused.contains(&LegacyEntryRef::Seed(seed_id_1)));
        assert!(unused.contains(&LegacyEntryRef::PrivateKey(key_id_1)));
        assert!(unused.contains(&LegacyEntryRef::PrivateKey(key_id_3)));
    }

    #[test]
    fn doesnt_report_ledger() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed_id_1 = vault.seeds().add(
            Seed::test_generate(None, "test-1".as_bytes(), None).unwrap()
        ).unwrap();

        let seed_id_2 = vault.seeds().add(
            Seed {
                source: SeedSource::Ledger(LedgerSource::default()),
                ..Seed::default()
            }
        ).unwrap();

        println!("init: {:?}, {:?}", seed_id_1, seed_id_2);

        let global_store = vault.global_key();
        global_store.create("test-g").unwrap();
        let global = Some(global_store.get().unwrap());

        let unused = vault.get_global_key_missing().unwrap();

        println!("{:?}", unused);

        assert_eq!(unused.len(), 1);

        assert!(unused.contains(&LegacyEntryRef::Seed(seed_id_1)));
    }
}
