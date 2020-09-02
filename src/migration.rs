pub mod source;
pub mod types;

use crate::migration::source::v1::V1Storage;
use crate::migration::source::v2::V2Storage;
use crate::migration::types::Migrate;
use std::path::{Path, PathBuf};

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

    let mut migration_v2 = V2Storage::create(path.clone());
    let migrated_v2 = migration_v2.migrate(path.clone());
    if migrated_v2.is_err() {
        error!("Failed to migrate from Vault V1 {:?}", migrated_v2.err())
    }
}

#[cfg(test)]
mod test_commons {
    use crate::structs::wallet::Wallet;
    use std::fs;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

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
                    .expect(format!("Failed to create: {:?}", target_path).as_str());
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).expect("File not read");
                f.write_all(&buf).expect("Not written");
            }
        }
    }

    #[allow(dead_code)]
    pub fn show_dir<P: AsRef<Path>>(dir: P, parent: Option<PathBuf>) {
        if dir.as_ref().is_dir() {
            for entry in fs::read_dir(dir.as_ref().clone()).unwrap() {
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
    pub fn sort_wallets(wallets: &mut Vec<Wallet>) {
        wallets.sort_by(|a, b| {
            a.get_entry(0)
                .unwrap()
                .address
                .unwrap()
                .cmp(&b.get_entry(0).unwrap().address.unwrap())
        });
    }
}
