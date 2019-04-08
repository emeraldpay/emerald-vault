//! # Migrate RocksDB key-value storage into filesystem storage

use std::path::Path;
use std::fs::read_dir;
use storage::keyfile::{FsStorage, DbStorage, KeystoreError};

///
pub struct MigrateController;

impl MigrateController {
    /// Migrate RocksDB storage into file system.
    /// Recursively scans folders and converts data to file storage.
    ///
    /// # Arguments
    ///
    /// * p - path to target db root folder
    ///
    pub fn migrate(p: &Path) -> Result<(), KeystoreError> {
        for e in read_dir(p)? {
            if e.is_err() {
                continue;
            }
            let dir = e.unwrap();

            let fs = FsStorage::new(dir.path());
            let db = DbStorage::new(dir.path())?;

            db.list_keyfiles().and_then(|kf| fs.put_batch(&kf))?;
        }

        Ok(())
    }

}

#[cfg(test)]
#[cfg(feature = "dev-dependencies")]
mod tests {
    use super::*;
    use tempdir::TempDir;
    use std::fs::File;

    #[test]
    fn should_migrate_rocksdb() {
        let dir = TempDir::new("emerald").unwrap();
        File::create(dir.path()).ok();
        let res = MigrateController::migrate(&dir.into_path());
        assert!(res.is_ok())
    }
}
