extern crate emerald;

extern crate rand;
extern crate rustc_serialize;
extern crate tempdir;
extern crate uuid;

use emerald::{Address, KECCAK256_BYTES};
use emerald::keystore::{CIPHER_IV_BYTES, Cipher, KDF_SALT_BYTES, Kdf, KdfDepthLevel, KeyFile, Prf};
use rustc_serialize::hex::{FromHex, ToHex};
use rustc_serialize::json;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempdir::TempDir;
use uuid::Uuid;

const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

macro_rules! arr {
    ($bytes: expr, $num: expr) => ({
        let mut arr = [0u8; $num];
        arr.copy_from_slice($bytes);
        arr
    })
}

#[test]
fn should_decrypt_private_key_protected_by_scrypt() {
    let path = keyfile_path("UTC--2017-03-17T10-52-08.\
                             229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");

    let keyfile = json::decode::<KeyFile>(&file_content(path)).unwrap();

    assert!(keyfile.decrypt_key("_").is_err());
    assert_eq!(keyfile.decrypt_key("1234567890").unwrap().to_hex(),
               "fa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f");
}

#[test]
fn should_decrypt_private_key_protected_by_pbkdf2() {
    let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");

    let keyfile = json::decode::<KeyFile>(&file_content(path)).unwrap();

    assert!(keyfile.decrypt_key("_").is_err());
    assert_eq!(keyfile.decrypt_key("1234567890").unwrap().to_hex(),
               "00b413b37c71bfb92719d16e28d7329dea5befa0d0b8190742f89e55617991cf");
}

#[test]
fn should_decode_keyfile_without_address() {
    let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");

    let exp = KeyFile {
        uuid: Uuid::from_str("37e0d14f-7269-7ca0-4419-d7b13abfeea9").unwrap(),
        dk_length: 32,
        kdf: Kdf::Pbkdf2 {
            prf: Prf::default(),
            c: 10240,
        },
        kdf_salt: arr!(&"095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b"
                            .from_hex()
                            .unwrap(),
                       KDF_SALT_BYTES),
        cipher: Cipher::default(),
        cipher_text: "9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126"
            .from_hex()
            .unwrap(),
        cipher_iv: arr!(&"58d54158c3e27131b0a0f2b91201aedc".from_hex().unwrap(),
                        CIPHER_IV_BYTES),
        keccak256_mac: arr!(&"83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63"
                                 .from_hex()
                                 .unwrap(),
                            KECCAK256_BYTES),
    };

    // just first encoding
    let key = json::decode::<KeyFile>(&file_content(path)).unwrap();

    // verify encoding & decoding full cycle logic
    let key = json::decode::<KeyFile>(&json::encode(&key).unwrap()).unwrap();

    assert_eq!(key, exp);
    assert_eq!(key.dk_length, exp.dk_length);
    assert_eq!(key.kdf, exp.kdf);
    assert_eq!(key.kdf_salt, exp.kdf_salt);
    assert_eq!(key.cipher_text, exp.cipher_text);
    assert_eq!(key.cipher_iv, exp.cipher_iv);
    assert_eq!(key.keccak256_mac, exp.keccak256_mac);
}

#[test]
fn should_decode_keyfile_with_address() {
    let path = keyfile_path("UTC--2017-03-17T10-52-08.\
                             229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");

    let exp = KeyFile {
        uuid: Uuid::from_str("f7ab2bfa-e336-4f45-a31f-beb3dd0689f3").unwrap(),
        dk_length: 32,
        kdf: Kdf::Scrypt {
            n: 1024,
            r: 8,
            p: 1,
        },
        kdf_salt: arr!(&"fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4"
                            .from_hex()
                            .unwrap(),
                       KDF_SALT_BYTES),
        cipher: Cipher::default(),
        cipher_text: "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1"
            .from_hex()
            .unwrap(),
        cipher_iv: arr!(&"9df1649dd1c50f2153917e3b9e7164e9".from_hex().unwrap(),
                        CIPHER_IV_BYTES),
        keccak256_mac: arr!(&"9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5"
                                 .from_hex()
                                 .unwrap(),
                            KECCAK256_BYTES),
    };

    // just first encoding
    let key = json::decode::<KeyFile>(&file_content(path)).unwrap();

    // verify encoding & decoding full cycle logic
    let key = json::decode::<KeyFile>(&json::encode(&key).unwrap()).unwrap();

    assert_eq!(key, exp);
    assert_eq!(key.dk_length, exp.dk_length);
    assert_eq!(key.kdf, exp.kdf);
    assert_eq!(key.kdf_salt, exp.kdf_salt);
    assert_eq!(key.cipher_text, exp.cipher_text);
    assert_eq!(key.cipher_iv, exp.cipher_iv);
    assert_eq!(key.keccak256_mac, exp.keccak256_mac);
}

#[test]
fn should_use_security_level() {
    let sec = KdfDepthLevel::Normal;
    let kf = KeyFile::new("1234567890", &sec).unwrap();
    assert_eq!(kf.kdf, Kdf::from(sec));

    let sec = KdfDepthLevel::High;
    let kf = KeyFile::new("1234567890", &sec).unwrap();
    assert_eq!(kf.kdf, Kdf::from(sec));
}

#[test]
fn should_flush_to_file() {
    let kf = KeyFile::new("1234567890", &KdfDepthLevel::Normal).unwrap();

    assert!(kf.flush(temp_dir().as_path(), None, None, None).is_ok());
}

#[test]
fn should_flush_to_file_with_meta() {
    let kf = KeyFile::new("1234567890", &KdfDepthLevel::Normal).unwrap();
    let name = Some(String::from("test name"));
    let descr = Some(String::from("test description"));

    assert!(kf.flush(temp_dir().as_path(), None, name, descr).is_ok());
}

#[test]
fn should_search_by_address() {
    let addr = "0x0047201aed0b69875b24b614dda0270bcd9f11cc"
        .parse::<Address>()
        .unwrap();

    let kf = KeyFile::search_by_address(&addr, &keystore_path()).unwrap();

    assert_eq!(kf.uuid,
               "f7ab2bfa-e336-4f45-a31f-beb3dd0689f3".parse().unwrap());
}

fn temp_dir() -> PathBuf {
    let dir = TempDir::new("emerald").unwrap();
    File::create(dir.path()).ok();
    dir.into_path()
}

fn file_content<P: AsRef<Path>>(path: P) -> String {
    let mut text = String::new();

    File::open(path)
        .expect("Expect read file content")
        .read_to_string(&mut text)
        .ok();

    text
}

fn keyfile_path(name: &str) -> PathBuf {
    let mut path = keystore_path();
    path.push(name);
    path
}

fn keystore_path() -> PathBuf {
    let mut buf = PathBuf::from(PRJ_DIR.expect("Expect project directory"));
    buf.push("tests/keystore/serialize");
    buf
}
