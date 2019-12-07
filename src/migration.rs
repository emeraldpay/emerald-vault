pub mod types;
pub mod source;

use std::path::Path;
use crate::migration::source::v2::V2Storage;
use crate::migration::types::Migrate;

pub fn auto_migrate<P, P2>(dir: P, target: P2)
    where P: AsRef<Path>, P2: AsRef<Path> {

    let mut migration_v2 = V2Storage::create(dir);
    migration_v2.migrate(target);

}
