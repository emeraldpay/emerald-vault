use std::path::PathBuf;
use std::fs;
use crate::migration::types::{MigrationResult, MigrationError, Migrate};
use crate::storage::default_path;

///
/// For V4 Vault we moved to a new directory.
/// Before V4 the Vault was stored in a non-standard location, and with V4 we started to use a location
/// more aligned with what OS expects. Ex. "Local Application Data" on Windows, org prefix on maxOS, XDG Base on Linux, etc.
/// See [`crate::storage`] for more details.
pub struct V4Storage {
    /// The specified directory for the Vault storage
    dir: PathBuf,

    /// Old path for migration. Provided here for ability to override in tests
    old_path: PathBuf,
    /// The expected default path for the Vault storage.
    default_path: PathBuf,

    migration: MigrationResult,
}

/// Old path (*nix)
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
fn old_path() -> Option<PathBuf> {
    let config_dir = home::home_dir();
    if config_dir.is_none() {
        return None;
    }
    let mut config_dir = config_dir.unwrap();
    config_dir.push(".emerald");
    config_dir.push("vault");
    Some(config_dir)
}

/// Old path (Mac OS X)
#[cfg(target_os = "macos")]
fn old_path() -> Option<PathBuf> {
    let config_dir = home::home_dir();
    if config_dir.is_none() {
        return None;
    }
    let mut config_dir = config_dir.unwrap();
    config_dir.push("Library");
    config_dir.push("Emerald");
    config_dir.push("vault");
    Some(config_dir)
}

/// Old path (Windows OS)
#[cfg(target_os = "windows")]
fn old_path() -> Option<PathBuf> {
    use std::env;
    let app_data_var = env::var("APPDATA");
    if app_data_var.is_err() {
        return None;
    }
    let mut config_dir = PathBuf::from(app_data_var.unwrap());
    config_dir.push(".emerald");
    config_dir.push("vault");
    Some(config_dir)
}

impl V4Storage {
    pub fn create(source: PathBuf) -> Self {
        let old_path = old_path().unwrap_or_else(|| PathBuf::from("/tmp/nonexistent"));
        Self {
            dir: source,
            old_path,
            default_path: default_path(),
            migration: MigrationResult::default(),
        }
    }

    /// Applies only if the directory is the default path for the Vault storage.
    /// I.e., we only migrate between the defaults.
    pub fn should_migrate(&self) -> bool {
        // Only migrate if:
        // 1. Current dir is the new default path
        // 2. Current dir is different from old path
        // 3. Old path exists as directory
        // 4. New path doesn't exist or is empty
        //
        // NOTE: the old path id set by default; i.e., we expect it as a default location for the old vault
        //       but we check that the new one is the default one.
        //
        self.dir == self.default_path
            && self.dir != self.old_path
            && self.old_path.exists()
            && self.old_path.is_dir()
            && (!self.dir.exists() || self.is_empty())
    }


    ///
    /// Check if the target directory is empty (no vault files or anything)
    /// It's important to verify that to avoid merging or overwriting the vault
    fn is_empty(&self) -> bool {
        if !self.dir.exists() {
            return true;
        }
        let files = fs::read_dir(&self.dir);
        if files.is_err() {
            return true;
        }
        let files = files.unwrap();
        files.count() == 0
    }

    /// Move all files and directories from old path to new path
    fn move_all_files(old_path: &PathBuf, new_path: &PathBuf, migration: &mut MigrationResult) -> Result<(), MigrationError> {
        // Ensure the new path exists
        if !new_path.exists() {
            fs::create_dir_all(new_path)
                .map_err(|e| MigrationError::OtherError(format!("Failed to create new vault directory: {}", e)))?;
        }

        let entries = fs::read_dir(old_path)
            .map_err(|e| MigrationError::OtherError(format!("Failed to read old vault directory: {}", e)))?;

        for entry in entries {
            let entry = entry
                .map_err(|e| MigrationError::OtherError(format!("Failed to read directory entry: {}", e)))?;
            let source_path = entry.path();
            let file_name = source_path.file_name()
                .ok_or_else(|| MigrationError::OtherError("Invalid file name".to_string()))?;
            let target_path = new_path.join(file_name);

            migration.info(format!("Moving {:?} to {:?}", source_path, target_path));

            // Use fs_extra for recursive copy and then remove source
            if source_path.is_dir() {
                let mut copy_options = fs_extra::dir::CopyOptions::new();
                copy_options.overwrite = false;
                copy_options.copy_inside = true;

                fs_extra::dir::copy(&source_path, new_path, &copy_options)
                    .map_err(|e| MigrationError::OtherError(format!("Failed to copy directory {:?}: {}", source_path, e)))?;

                fs::remove_dir_all(&source_path)
                    .map_err(|e| MigrationError::OtherError(format!("Failed to remove old directory {:?}: {}", source_path, e)))?;
            } else {
                fs::rename(&source_path, &target_path)
                    .map_err(|e| MigrationError::OtherError(format!("Failed to move file {:?}: {}", source_path, e)))?;
            }
        }

        Ok(())
    }

    /// Execute the migration
    fn execute(&mut self) -> Result<(), MigrationError> {
        Self::move_all_files(&self.old_path, &self.dir, &mut self.migration)
    }
}

impl Migrate for V4Storage {
    fn migrate<P>(&mut self, target: P) -> Result<&MigrationResult, MigrationError>
    where P: std::convert::AsRef<std::path::Path> {
        if target.as_ref() != self.dir.as_path() {
            self.migration.error(format!("Migration is supposed to run within the same dir. {:?} != {:?}", self.dir, target.as_ref()));
            return Err(MigrationError::OtherError("Invalid dir".to_string()));
        }
        if self.should_migrate() {
            self.execute()?;
        }
        Ok(&self.migration)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use tempdir::TempDir;
    use crate::migration::source::v4::V4Storage;
    use crate::migration::types::{MigrationResult};

    /// Creates temporary test paths for migration testing
    /// NOTE: it doesn't create the directories itself, just the paths
    fn create_test_paths() -> (PathBuf, PathBuf, PathBuf) {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v4").unwrap().into_path();
        let old_path = tmp_dir.join("old_vault");
        let new_path = tmp_dir.join("new_vault");
        (tmp_dir, old_path, new_path)
    }

    /// Creates a V4Storage instance for testing
    fn create_v4_storage(old_path: PathBuf, new_path: PathBuf, default_path: Option<PathBuf>) -> V4Storage {
        V4Storage {
            dir: new_path.clone(),
            default_path: default_path.unwrap_or(new_path),
            old_path,
            migration: MigrationResult::default(),
        }
    }

    /// Creates standard vault files with content in the specified directory
    fn create_vault_files(path: &PathBuf) {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("global.key"), "key_content").unwrap();
        fs::write(path.join("wallet.wallet"), "wallet_content").unwrap();
        fs::write(path.join("seed.seed"), "seed_content").unwrap();
    }

    /// Verifies that files were successfully moved from old to new path
    fn assert_files_moved(old_path: &PathBuf, new_path: &PathBuf, files: &[&str]) {
        for file in files {
            assert!(new_path.join(file).exists(), "File {} should exist in new path", file);
        }
        let remaining_entries: Vec<_> = fs::read_dir(old_path).unwrap().collect();
        assert_eq!(remaining_entries.len(), 0, "Old directory should be empty after migration");
    }

    #[test]
    fn should_migrate_returns_false_when_old_path_missing() {
        // It doesn't create the directories
        let (_, old_path, new_path) = create_test_paths();

        let storage = create_v4_storage(old_path.clone(), new_path.clone(), Some(new_path.clone()));

        // Should not migrate when the old path doesn't exist
        assert!(!old_path.exists(), "Old path should not exist for this test");
        assert!(!storage.should_migrate());
    }

    #[test]
    fn is_not_empty_when_vault_files_exist() {
        let (_, old_path, new_path) = create_test_paths();

        // Create the new directory with vault content
        fs::create_dir_all(&new_path).unwrap();
        fs::write(new_path.join("existing.key"), "content").unwrap();

        let storage = create_v4_storage(old_path, new_path.clone(), Some(new_path));

        assert!(!storage.is_empty());
    }

    #[test]
    fn move_handles_files_and_directories_with_complex_structure() {
        let (_, old_path, new_path) = create_test_paths();

        // Create old directory with mixed content
        create_vault_files(&old_path);
        fs::write(old_path.join("readme.txt"), "readme_content").unwrap();

        // Create archive directory with nested content
        fs::create_dir_all(old_path.join(".archive")).unwrap();
        fs::write(old_path.join(".archive").join("archived.key"), "archived_content").unwrap();
        fs::create_dir_all(old_path.join(".archive").join("subdir")).unwrap();
        fs::write(old_path.join(".archive").join("subdir").join("nested.txt"), "nested_content").unwrap();

        // Create complex directory structure for permissions test
        fs::create_dir_all(old_path.join("level1").join("level2")).unwrap();
        fs::write(old_path.join("level1").join("level2").join("deep.key"), "deep_content").unwrap();

        // Create multiple archive directories
        fs::create_dir_all(old_path.join(".archive").join("2024-01-01")).unwrap();
        fs::create_dir_all(old_path.join(".archive").join("2024-01-02")).unwrap();
        fs::write(old_path.join(".archive").join("2024-01-01").join("test1.key"), "test1").unwrap();
        fs::write(old_path.join(".archive").join("2024-01-02").join("test2.key"), "test2").unwrap();

        let mut migration_result = MigrationResult::default();
        let result = V4Storage::move_all_files(&old_path, &new_path, &mut migration_result);

        assert!(result.is_ok());
        assert!(migration_result.logs.len() > 0);

        // Verify all standard vault files were moved
        assert_files_moved(&old_path, &new_path, &["global.key", "wallet.wallet", "seed.seed"]);

        // Verify complex structure is preserved
        assert!(new_path.join("level1").join("level2").join("deep.key").exists());
        assert_eq!(fs::read_to_string(new_path.join("level1").join("level2").join("deep.key")).unwrap(), "deep_content");

        // Verify multiple archive directories are preserved
        assert!(new_path.join(".archive").join("2024-01-01").join("test1.key").exists());
        assert!(new_path.join(".archive").join("2024-01-02").join("test2.key").exists());
        assert_eq!(fs::read_to_string(new_path.join(".archive").join("2024-01-01").join("test1.key")).unwrap(), "test1");
        assert_eq!(fs::read_to_string(new_path.join(".archive").join("2024-01-02").join("test2.key")).unwrap(), "test2");

        // Verify nested content is preserved
        assert_eq!(fs::read_to_string(new_path.join(".archive").join("subdir").join("nested.txt")).unwrap(), "nested_content");
    }

    #[test]
    fn move_creates_new_directory() {
        let (tmp_dir, old_path, _) = create_test_paths();
        let new_path = tmp_dir.join("non_existent").join("new_vault");

        // Create old directory with content
        create_vault_files(&old_path);

        let mut migration_result = MigrationResult::default();
        let result = V4Storage::move_all_files(&old_path, &new_path, &mut migration_result);

        assert!(result.is_ok());
        assert!(new_path.exists());
        assert_files_moved(&old_path, &new_path, &["global.key", "wallet.wallet", "seed.seed"]);
    }

    #[test]
    fn migrate_full_flow() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v4").unwrap().into_path();

        // Create old directory structure similar to what would exist
        let old_path = tmp_dir.join("old_vault");
        fs::create_dir_all(&old_path).unwrap();
        fs::write(old_path.join("global.key"), "global_key_content").unwrap();
        fs::write(old_path.join("b6923a7f-033f-4370-8861-2621871aeeec.wallet"), "wallet_content").unwrap();
        fs::write(old_path.join("7dc9347a-5ef0-4dc3-bae1-d75d20b1259c.seed"), "seed_content").unwrap();
        fs::write(old_path.join("addressbook.csv"), "csv_content").unwrap();
        fs::write(old_path.join("random_file.txt"), "random_content").unwrap();

        // Create .archive with nested structure
        fs::create_dir_all(old_path.join(".archive").join("2024-01-01")).unwrap();
        fs::write(old_path.join(".archive").join("2024-01-01").join("old_wallet.wallet"), "old_wallet_content").unwrap();

        let new_path = tmp_dir.join("new_vault");

        // Create storage instance that would trigger migration
        let mut migration = V4Storage {
            dir: new_path.clone(),
            default_path: new_path.clone(),
            old_path: old_path.clone(),
            migration: MigrationResult::default(),
        };

        // Manually test the move_all_files functionality directly
        let result = migration.execute();

        assert!(result.is_ok());

        // Verify all content was moved
        assert!(new_path.join("global.key").exists());
        assert!(new_path.join("b6923a7f-033f-4370-8861-2621871aeeec.wallet").exists());
        assert!(new_path.join("7dc9347a-5ef0-4dc3-bae1-d75d20b1259c.seed").exists());
        assert!(new_path.join("addressbook.csv").exists());
        assert!(new_path.join("random_file.txt").exists());
        assert!(new_path.join(".archive").join("2024-01-01").join("old_wallet.wallet").exists());

        // Verify content integrity
        assert_eq!(fs::read_to_string(new_path.join("global.key")).unwrap(), "global_key_content");
        assert_eq!(fs::read_to_string(new_path.join(".archive").join("2024-01-01").join("old_wallet.wallet")).unwrap(), "old_wallet_content");

        // Verify old directory is cleaned up
        let remaining_entries: Vec<_> = fs::read_dir(&old_path).unwrap().collect();
        assert_eq!(remaining_entries.len(), 0, "Old directory should be empty after migration");
    }

    #[test]
    fn should_not_migrate_when_not_default_path() {
        let (tmp_dir, old_path, new_path) = create_test_paths();
        // Create old directory with content
        create_vault_files(&old_path);

        // Use a custom path (not default path) as target
        let new_path_default = tmp_dir.join("different_vault_default");
        let storage = create_v4_storage(old_path, new_path.clone(), Some(new_path_default));

        // Should not migrate because target dir != default_path()
        assert!(!storage.should_migrate());
    }

}
