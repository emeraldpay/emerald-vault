use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use crate::migration::types::{Migrate, MigrationError, MigrationResult};
use crate::storage::{default_path, global_key};

///
/// V3 Vault just keeps files under different directory by default. So as a migration it checks if
/// the Vault is empty, and it's on default path and there is a vault files in parent directory. In
/// this case it moves files from the parent dir to the current.
pub struct V3Storage {
    /// Main directory for the Vault storage
    dir: PathBuf,
    /// System default path to the Vault storage. Provided here for
    /// an ability to change it for a custom setup
    default_path: PathBuf,
    migration: MigrationResult,
}

impl V3Storage {

    pub fn create(source: PathBuf) -> V3Storage {
        V3Storage {
            dir: source,
            migration: MigrationResult::default(),
            default_path: default_path(),
        }
    }

    fn should_migrate(&self) -> bool {
        self.is_default() && self.is_empty() && self.parent_is_set()
    }

    fn is_default(&self) -> bool {
        self.default_path.eq(&self.dir)
    }

    fn is_empty(&self) -> bool {
        if !self.dir.exists() {
            return true
        }
        let gk = self.dir.join(global_key::KEY_FILE);
        !gk.exists()
    }

    ///
    /// Check if parent dir is also a vault. I.e., check if the current Vault setup is a subdir
    /// of a previous location, and that location contains old files
    fn parent_is_set(&self) -> bool {
        let parent = self.dir.parent();
        if parent.is_none() {
            return false
        }
        let parent = parent.unwrap();
        if !parent.is_dir() {
            return false
        }
        let files = fs::read_dir(parent);
        if files.is_err() {
            return false
        }
        let files = files.unwrap();
        // simply check if any file in that dir looks like a part of a vault
        for entry in files.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "key" || ext == "wallet" || ext == "seed" {
                        return true
                    }
                }
            }
        }
        false
    }

    ///
    /// Check if the file belongs to a Vault so must be moved to a new place
    fn should_move(path: &Path) -> bool {
        // extract actual filename
        let file_name = path.file_name()
            .unwrap_or(OsStr::new("-"))
            .to_str().unwrap_or("-");
        if let Some(ext) = path.extension() {
            if ext == "key" || ext == "wallet" || ext == "seed" || ext == "bak" {
               return true
            }
        }
        file_name == "addressbook.csv" || file_name == ".archive"
    }

    ///
    /// Get all files on the specified dir that must be moved to a new location
    fn files_to_move(parent: PathBuf) -> Result<Vec<PathBuf>, MigrationError> {
        if !parent.is_dir() {
            return Err(MigrationError::OtherError(format!("Parent is not a dir: {:?}", parent)))
        }
        let files = fs::read_dir(parent)
            .map_err(|e| MigrationError::OtherError(format!("Failed to read the dir. {}", e)))?;
        let mut result = vec![];
        for entry in files.flatten() {
            let path = entry.path();
            let should_move = V3Storage::should_move(&path);
            if should_move {
                result.push(path)
            }
        }
        Ok(result)
    }

    ///
    /// Actual moving of the `files` to the `dir`.
    /// NOTE: in general it works if the source and target dir are in the same filesystem, because it uses a standard rename of files.
    fn move_files(files: Vec<PathBuf>, dir: &Path, migration: &mut MigrationResult) -> Result<(), MigrationError> {
        for f in files {
            let target = dir.join(f.file_name().unwrap());
            migration.info(
                format!("Moving {:?} to {:?}", f, target)
            );
            fs::rename(f, target)
                .map_err(|e| MigrationError::OtherError(format!("Failed to move file: {}", e)))?
        }
        Ok(())
    }

    fn execute(&mut self) -> Result<(), MigrationError> {
        let files = V3Storage::files_to_move(self.dir.parent().unwrap().to_path_buf())?;
        V3Storage::move_files(files, &self.dir, &mut self.migration)
    }
}

impl Migrate for V3Storage {
    fn migrate<P>(&mut self, target: P) -> Result<&MigrationResult, MigrationError> where P: AsRef<Path> {
        if target.as_ref() != self.dir.as_path() {
            self.migration.error(format!("Migration is supposed to run withing the same dir. {:?} != {:?}", self.dir, target.as_ref()));
            return Err(MigrationError::OtherError("Invalid dir".to_string()))
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
    use tempdir::TempDir;
    use itertools::Itertools;
    use crate::migration::source::v3::V3Storage;
    use crate::migration::types::{Migrate, MigrationResult};

    #[test]
    fn accepts_seed() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        let act = V3Storage::should_move(
            &tmp_dir.join("7dc9347a-5ef0-4dc3-bae1-d75d20b1259c.seed")
        );
        assert!(act);
    }

    #[test]
    fn accepts_key() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        let act = V3Storage::should_move(
            &tmp_dir.join("130d0800-462c-4c48-8b4a-94cef23351a2.key")
        );
        assert!(act);
    }

    #[test]
    fn accepts_bak() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        let act = V3Storage::should_move(
            &tmp_dir.join("130d0800-462c-4c48-8b4a-94cef23351a2.key.bak")
        );
        assert!(act);
    }

    #[test]
    fn accepts_global_key() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        let act = V3Storage::should_move(
            &tmp_dir.join("global.key")
        );
        assert!(act);
    }

    #[test]
    fn accepts_wallet() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        let act = V3Storage::should_move(
            &tmp_dir.join("b6923a7f-033f-4370-8861-2621871aeeec.wallet")
        );
        assert!(act);
    }

    #[test]
    fn accepts_addressbook() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        let act = V3Storage::should_move(
            &tmp_dir.join("addressbook.csv")
        );
        assert!(act);
    }

    #[test]
    fn accepts_archive() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        let act = V3Storage::should_move(
            &tmp_dir.join(".archive")
        );
        assert!(act);
    }

    #[test]
    fn ignores_vault() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        let act = V3Storage::should_move(
            &tmp_dir.join("vault")
        );
        assert!(!act);
    }

    #[test]
    fn list_actual_files() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        fs::write(tmp_dir.join("global.key"), "").unwrap();
        fs::write(tmp_dir.join("b6923a7f-033f-4370-8861-2621871aeeec.wallet"), "").unwrap();
        fs::write(tmp_dir.join("7dc9347a-5ef0-4dc3-bae1-d75d20b1259c.seed"), "").unwrap();
        fs::write(tmp_dir.join("readme.txt"), "").unwrap();

        let act = V3Storage::files_to_move(tmp_dir).unwrap();

        let files = act.iter()
            .map(|a| a.file_name().unwrap().to_str().unwrap())
            .sorted()
            .join(", ");

        assert_eq!(files, "7dc9347a-5ef0-4dc3-bae1-d75d20b1259c.seed, b6923a7f-033f-4370-8861-2621871aeeec.wallet, global.key");
    }

    #[test]
    fn move_files() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        fs::write(tmp_dir.join("global.key"), "1").unwrap();
        fs::write(tmp_dir.join("b6923a7f-033f-4370-8861-2621871aeeec.wallet"), "22").unwrap();
        fs::write(tmp_dir.join("7dc9347a-5ef0-4dc3-bae1-d75d20b1259c.seed"), "333").unwrap();
        fs::write(tmp_dir.join("readme.txt"), "4444").unwrap();
        fs::create_dir(tmp_dir.join(".archive")).unwrap();
        fs::write(tmp_dir.join(".archive").join("test.txt"), "55555").unwrap();

        let target = tmp_dir.join("vault");
        fs::create_dir(&target).unwrap();

        let files = V3Storage::files_to_move(tmp_dir.clone()).unwrap();
        let act = V3Storage::move_files(files, &target, &mut MigrationResult::default());

        assert!(act.is_ok());

        let target_files = fs::read_dir(&target)
            .unwrap()
            .map(|f| f.unwrap().file_name().to_str().unwrap().to_string())
            .sorted()
            .join(", ");
        assert_eq!(target_files, ".archive, 7dc9347a-5ef0-4dc3-bae1-d75d20b1259c.seed, b6923a7f-033f-4370-8861-2621871aeeec.wallet, global.key");

        let original_files = fs::read_dir(&tmp_dir)
            .unwrap()
            .map(|f| f.unwrap().file_name().to_str().unwrap().to_string())
            .sorted()
            .join(", ");
        assert_eq!(original_files, "readme.txt, vault");
    }

    #[test]
    fn migrate() {
        let tmp_dir = TempDir::new("emerald-vault-migrate-v3").unwrap().into_path();
        fs::write(tmp_dir.join("global.key"), "1").unwrap();
        fs::write(tmp_dir.join("b6923a7f-033f-4370-8861-2621871aeeec.wallet"), "22").unwrap();
        fs::write(tmp_dir.join("7dc9347a-5ef0-4dc3-bae1-d75d20b1259c.seed"), "333").unwrap();
        fs::write(tmp_dir.join("readme.txt"), "4444").unwrap();
        fs::create_dir(tmp_dir.join(".archive")).unwrap();
        fs::write(tmp_dir.join(".archive").join("test.txt"), "55555").unwrap();

        let target = tmp_dir.join("vault");
        fs::create_dir(&target).unwrap();

        let mut migration = V3Storage {
            default_path: target.clone(),
            ..V3Storage::create(target.clone())
        };
        let result = migration.migrate(target.clone()).unwrap();

        assert!(result.logs.len() > 1);

        let target_files = fs::read_dir(&target)
            .unwrap()
            .map(|f| f.unwrap().file_name().to_str().unwrap().to_string())
            .sorted()
            .join(", ");
        assert_eq!(target_files, ".archive, 7dc9347a-5ef0-4dc3-bae1-d75d20b1259c.seed, b6923a7f-033f-4370-8861-2621871aeeec.wallet, global.key");

        let original_files = fs::read_dir(&tmp_dir)
            .unwrap()
            .map(|f| f.unwrap().file_name().to_str().unwrap().to_string())
            .sorted()
            .join(", ");
        assert_eq!(original_files, "readme.txt, vault");
    }

}
