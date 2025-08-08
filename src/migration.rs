pub mod source;
pub mod types;

use crate::migration::{
    source::{v1::V1Storage},
    types::Migrate,
};
use std::path::{Path, PathBuf};
use crate::migration::source::v3::V3Storage;
use crate::migration::source::v4::V4Storage;

pub fn auto_migrate<P>(dir: P)
where
    P: AsRef<Path>,
{
    let path = PathBuf::from(dir.as_ref());

    let mut migration_v1 = V1Storage::create(path.clone());
    let migrated_v1 = migration_v1.migrate(path.clone());
    if migrated_v1.is_err() {
        error!("Failed to migrate from Vault V1 {:?}", migrated_v1.err())
    }

    //
    // V2 is skipped as too heavy.
    // The migration was supported by Emerald Wallet v2.2.0-v2.5.x
    //

    let mut migration_v3 = V3Storage::create(path.clone());
    let migrated_v3 = migration_v3.migrate(path.clone());
    if migrated_v3.is_err() {
        error!("Failed to migrate from Vault V3 {:?}", migrated_v3.err())
    }

    let mut migration_v4 = V4Storage::create(path.clone());
    let migrated_v4 = migration_v4.migrate(path.clone());
    if migrated_v4.is_err() {
        error!("Failed to migrate from Vault V4 {:?}", migrated_v4.err())
    }
}

#[cfg(test)]
mod test_commons {
    use crate::{
        structs::{book::AddressRef, wallet::Wallet},
        EthereumAddress,
    };
    use std::{
        fs,
        fs::File,
        io::{Read, Write},
        path::{Path, PathBuf},
    };

    pub fn unzip<P: AsRef<Path>>(src: P, target: PathBuf) {
        let file = File::open(src).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        for i in 0..zip.len() {
            let mut file = zip.by_index(i).unwrap();
            let target_path = target.join(file.name());
            //            println!("Filename: {}", file.name());
            if file.is_dir() {
                fs::create_dir(target_path).unwrap();
            } else {
                let mut f = File::create(target_path.clone())
                    .unwrap_or_else(|_| panic!("Failed to create: {:?}", target_path));
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).expect("File not read");
                f.write_all(&buf).expect("Not written");
            }
        }
    }

    #[allow(dead_code)]
    pub fn show_dir<P: AsRef<Path>>(dir: P, parent: Option<PathBuf>) {
        if dir.as_ref().is_dir() {
            for entry in fs::read_dir(dir.as_ref()).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    show_dir(&path, Some(dir.as_ref().to_path_buf()));
                } else {
                    let x = match parent {
                        Some(ref p) => p.join(path),
                        None => path,
                    };
                    println!("Filename: {:?}", x);
                }
            }
        }
    }

    fn as_ethereum_address(r: &AddressRef) -> EthereumAddress {
        match r {
            AddressRef::EthereumAddress(e) => *e,
            _ => panic!("not ethereum"),
        }
    }

    pub fn sort_wallets(wallets: &mut Vec<Wallet>) {
        wallets.sort_by(|a, b| {
            let addr_a = as_ethereum_address(&a.get_entry(0).unwrap().address.unwrap());
            let addr_b = as_ethereum_address(&b.get_entry(0).unwrap().address.unwrap());
            addr_a.cmp(&addr_b)
        });
    }
}
