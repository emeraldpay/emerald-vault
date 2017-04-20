///! # Functionality for `KeyFile` packing

use address::Address;
use chrono::prelude::*;
use key_generator::private_key::{PRIVATE_KEY_BYTES, PrivateKey};
use keystore::KeyFile;
use rustc_serialize::json;
use secp256k1::Error as SecpError;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use uuid::Uuid;


/// Creates a new `KeyFile` with a specified `Address`
///
/// # Arguments
///
/// * `pk` - private key for inserting in a `KeyFile`
/// * `passphrase` - password for encryption of private key
/// * `addr` - optional address to be included in `KeyFile`
///
pub fn create_keyfile(pk: PrivateKey,
                      passphrase: &str,
                      addr: Option<Address>)
                      -> Result<KeyFile, SecpError> {
    let mut kf = KeyFile::default();
    let pk_data: [u8; PRIVATE_KEY_BYTES] = pk.into();

    match addr {
        Some(a) => kf.with_address(&a),
        _ => {}
    }
    kf.init_crypto();
    kf.insert_key(&pk_data, passphrase);

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

    let mut file = File::create(&path).expect("Expect to create file for KeyFile");
    let data = json::encode(&kf).expect("Expect to encode KeyFile");
    file.write_all(data.as_ref());

    Ok(file)
}

/// Time stamp for key file in format `<timestamp>Z`
pub fn get_timestamp() -> String {
    let mut stamp = UTC::now().to_rfc3339();
    stamp.push_str("Z");

    stamp
}
