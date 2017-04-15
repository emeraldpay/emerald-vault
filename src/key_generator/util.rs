//! # Helper methods for Secret key generator

use address::{ADDRESS_BYTES, Address};
use chrono::prelude::*;
use crypto::digest::Digest;
use crypto::sha3::{Sha3, Sha3Mode};
use key_generator::{Generator, SECP256K1};
use keystore::KeyFile;
use rustc_serialize::json;
use secp256k1::{Error as SecpError, Secp256k1};
use secp256k1::key::{PublicKey, SecretKey};
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use uuid::Uuid;


/// Creates a new public key from a secret key.
pub fn to_public(sec: &SecretKey) -> Result<PublicKey, SecpError> {
    PublicKey::from_secret_key(&SECP256K1, sec)
}

/// Creates a new address from a secret key.
pub fn to_address(sec: &SecretKey) -> Result<Address, SecpError> {
    let mut res: [u8; 32] = [0; 32];
    let mut sha3 = Sha3::new(Sha3Mode::Keccak256);
    let pk_data = to_public(sec)
        .and_then(|i| Ok(i.serialize_vec(&SECP256K1, false)))
        .unwrap();

    sha3.input(&pk_data);
    sha3.result(&mut res);

    let mut addr_data: [u8; ADDRESS_BYTES] = [0u8; 20];
    addr_data.copy_from_slice(&res[12..]);

    Ok(Address::new(addr_data))
}

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
    use rand::OsRng;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn get_temp_dir() -> PathBuf {
        let p = env::temp_dir();
        let dir = p.join(get_timestamp());
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn should_convert_to_address() {
        let rng = OsRng::new().unwrap();
        let mut gen = Generator::new(rng);
        let sk = gen.get();

        let address = to_address(&sk);

        assert!(address.is_ok());
    }

    #[test]
    fn should_convert_to_public() {
        let mut rng = OsRng::new().unwrap();
        let (sk, pk) = SECP256K1.generate_keypair(&mut rng).unwrap();
        let extracted = to_public(&sk).unwrap();

        assert_eq!(pk, extracted);
    }

    #[test]
    fn should_create_keyfile() {
        let temp_dir = get_temp_dir();
        let rng = OsRng::new().unwrap();
        let mut gen = Generator::new(rng);
        let sk = gen.get();

        let file = to_address(&sk)
            .and_then(create_keyfile)
            .and_then(|k| to_file(k, Some(&temp_dir)));

        assert!(file.is_ok());

        fs::remove_file(&temp_dir);
    }

    #[test]
    fn should_use_correct_filename() {}
}
