///! #functionality for `KeyFile` packing

use address::Address;
use chrono::prelude::*;
use keystore::KeyFile;
use rustc_serialize::json;
use secp256k1::Error as SecpError;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use uuid::Uuid;


/// Creates a new `KeyFile` with a specified `Address`
pub fn create_keyfile(addr: Address) -> Result<KeyFile, SecpError> {
    let mut kf = KeyFile::default();
    kf.with_address(&addr);

    Ok(kf)
}

/// Serializes KeyFile into JSON file with name `UTC-<timestamp>Z--<uuid>`
///
/// # Arguments
///
/// * `kf` - `KeyFile`
/// * `dir` - path to destination directory
///
pub fn to_file(kf: KeyFile, dir: Option<&Path>) -> Result<File, SecpError> {
    let mut name: String = "UTC-".to_string();
    name.push_str(&get_timestamp());
    name.push_str("--");
    name.push_str(&Uuid::new_v4().to_string());

    let mut p: PathBuf = PathBuf::new();
    let path = match dir {
        Some(dir) => {
            p = PathBuf::from(dir).with_file_name(name);
            p.as_path()
        }
        None => Path::new(&name),
    };

    let mut file = File::create(&path).expect("Expect to create key file");
    let data = json::encode(&kf).expect("Expect to encode KeyFile");
    file.write_all(data.as_ref());

    Ok(file)
}

fn get_timestamp() -> String {
    let stamp = UTC::now();
    stamp.to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_generator::Generator;
    use rand::OsRng;
    use std::{env, fs};
    use std::path::{Path, PathBuf};

    fn _temp_dir() -> PathBuf {
        let p = env::temp_dir();
        let dir = p.join(get_timestamp());
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn should_create_keyfile() {
        let temp_dir = _temp_dir();
        let rng = OsRng::new().unwrap();
        let mut gen = Generator::new(rng);
        let sk = gen.get();

        let file = sk.to_address()
            .and_then(create_keyfile)
            .and_then(|k| to_file(k, Some(&temp_dir)));

        assert!(file.is_ok());

        fs::remove_file(&temp_dir);
    }

    #[test]
    fn should_use_correct_filename() {}
}
