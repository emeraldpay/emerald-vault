#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate emerald_vault_core;
extern crate emerald_vault_proto;
extern crate uuid;
extern crate rocksdb;
extern crate hex;
#[macro_use]
extern crate log;
extern crate glob;

use std::path::Path;
use crate::source::v2::V2Storage;
use crate::migration::types::Migrate;

pub mod migration;
pub mod source;


pub fn auto_migrate<P, P2>(dir: P, target: P2)
    where P: AsRef<Path>, P2: AsRef<Path> {

    let mut migration_v2 = V2Storage::create(dir);
    migration_v2.migrate(target);

}
