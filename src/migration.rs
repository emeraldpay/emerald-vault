pub mod types;
pub mod source;

use std::path::{Path, PathBuf};
use crate::migration::source::v1::V1Storage;
use crate::migration::source::v2::V2Storage;
use crate::migration::types::Migrate;

pub fn auto_migrate<P>(dir: P)
    where P: AsRef<Path> {

    let path = PathBuf::from(dir.as_ref());


    let mut migration_v1 = V1Storage::create(path.clone());
    let migrated_v1 = migration_v1.migrate(path.clone());
    if migrated_v1.is_err() {
        error!("Failed to migrate from Vault V1 {:?}", migrated_v1.err())
    }

    let mut migration_v2 = V2Storage::create(path.clone());
    let migrated_v2 = migration_v2.migrate(path.clone());
    if migrated_v2.is_err() {
        error!("Failed to migrate from Vault V1 {:?}", migrated_v2.err())
    }

}
