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
    migration_v1.migrate(path.clone());

    let mut migration_v2 = V2Storage::create(path.clone());
    migration_v2.migrate(path.clone());

}
