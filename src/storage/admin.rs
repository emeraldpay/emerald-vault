use uuid::Uuid;
use crate::storage::archive::{Archive, ArchiveType};
use crate::storage::vault::VaultStorage;
use crate::structs::pk::PrivateKeyHolder;
use crate::structs::seed::Seed;
use crate::structs::types::UsesGlobalKey;

///
/// Utility operations to administrate the Vault Storage
pub struct VaultAdmin {
    vault: VaultStorage,
}

impl VaultAdmin {
    pub fn create(vault: VaultStorage) -> VaultAdmin {
        VaultAdmin {
            vault
        }
    }

    ///
    /// _Tries_ to re-encrypt Secrets encrypted with an individual password, i.e., which are not using the Global Key.
    /// It checks provided `legacy_password` against each of them, and where it decrypt the Secret it re-encrypts with using Global Key. I.e.,
    /// this function may upgrade multiple vault items, or none at all if the provided legacy password is incorrect. It doesn't produce any error,
    /// only returns a list of items successfully upgraded.
    ///
    /// Params:
    /// - `legacy_password` a password that some of legacy encrypted elements _may_ have
    /// - `global_password` password for the Global Key
    ///
    /// Returns list or successfully re-encrypted object. Can be id of a Seed or a Private Key.
    pub fn upgrade_all_legacy(&self, legacy_password: &str, global_password: &str) -> Vec<Uuid> {
        if !self.vault.global_key().is_set() {
            return vec![]
        }

        let mut result: Vec<Uuid> = Vec::new();
        let archive = Archive::create(&self.vault.dir, ArchiveType::Update);
        let global = self.vault.global_key().get().expect("GlobalKey is not available");

        self.vault.seeds()
            .list_entries().unwrap_or(vec![])
            .iter()
            .filter(|seed| !seed.is_using_global())
            .for_each(|seed| {
                let id = seed.id;
                let updated = seed.clone().source.reencrypt(legacy_password.as_bytes(), global_password.as_bytes(), global.clone());
                if updated.is_ok() {
                    let seed = Seed {
                        source: updated.unwrap(),
                        ..seed.clone()
                    };
                    if self.vault.seeds().update_multiple(seed, &archive).is_ok() {
                        result.push(id)
                    }
                }
            });

        self.vault.keys()
            .list_entries().unwrap_or(vec![])
            .iter()
            .filter(|key| !key.is_using_global())
            .for_each(|key| {
                let id = key.id;
                let updated = key.clone().reencrypt(legacy_password.as_bytes(), global_password.as_bytes(), global.clone());
                if updated.is_ok() {
                    if self.vault.keys().update_multiple(updated.unwrap(), &archive).is_ok() {
                        result.push(id.clone())
                    }
                }
            });

        archive.finalize();

        result
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;
    use crate::storage::admin::VaultAdmin;
    use crate::storage::vault::VaultStorage;
    use crate::structs::pk::PrivateKeyHolder;
    use crate::structs::seed::Seed;
    use crate::structs::types::UsesGlobalKey;

    #[test]
    fn try_all_upgrades() {
        let tmp_dir = TempDir::new("emerald-global-key-test").unwrap();
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed_id_1 = vault.seeds().add(
            Seed::test_generate(None, "test-1".as_bytes(), None).unwrap()
        ).unwrap();

        let key_id_1 = vault.keys().add(
            PrivateKeyHolder::generate_ethereum_raw("test-2").unwrap()
        ).unwrap();

        let key_id_2 = vault.keys().add(
            PrivateKeyHolder::generate_ethereum_raw("test-3").unwrap()
        ).unwrap();

        let key_id_3 = vault.keys().add(
            PrivateKeyHolder::generate_ethereum_raw("test-2").unwrap()
        ).unwrap();

        println!("init: {:?}, {:?}, {:?}, {:?}", seed_id_1, key_id_1, key_id_2, key_id_3);

        let admin = VaultAdmin::create(vault.clone());
        let global_store = vault.global_key();
        global_store.create("test-g").unwrap();

        let upgraded = admin.upgrade_all_legacy("test-wrong", "test-g");
        println!("Upgraded: {:?}", upgraded);
        assert!(upgraded.is_empty());

        let upgraded = admin.upgrade_all_legacy("test-1", "test-g");
        println!("Upgraded: {:?}", upgraded);
        assert_eq!(upgraded.len(), 1);
        assert!(vault.seeds().get(seed_id_1).unwrap().is_using_global());

        let upgraded = admin.upgrade_all_legacy("test-2", "test-g");
        println!("Upgraded: {:?}", upgraded);
        assert_eq!(upgraded.len(), 2);
        assert!(vault.keys().get(key_id_1).unwrap().is_using_global());
        assert!(!vault.keys().get(key_id_2).unwrap().is_using_global());
        assert!(vault.keys().get(key_id_3).unwrap().is_using_global());

        let upgraded = admin.upgrade_all_legacy("test-3", "test-g");
        println!("Upgraded: {:?}", upgraded);
        assert_eq!(upgraded.len(), 1);
        assert!(vault.keys().get(key_id_1).unwrap().is_using_global());
        assert!(vault.keys().get(key_id_2).unwrap().is_using_global());
        assert!(vault.keys().get(key_id_3).unwrap().is_using_global());
    }
}
