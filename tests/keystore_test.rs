extern crate emerald;

extern crate rustc_serialize;
extern crate uuid;

use emerald::keystore::*;
use rustc_serialize::hex::FromHex;
use rustc_serialize::json;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use uuid::Uuid;

const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

macro_rules! arr {
    ($bytes: expr, $num: expr) => ({
        let mut arr = [0u8; $num];

        arr.clone_from_slice($bytes);

        arr
    })
}

#[test]
fn should_extract_scrypt_based_kdf_private_key() {
    let path = keyfile_path("UTC--2017-03-17T10-52-08.\
                             229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");

    let key = json::decode::<emerald::KeyFile>(&file_content(path)).unwrap();

    assert!(key.extract_key("_").is_err());
    assert_eq!(&key.extract_key("1234567890").unwrap(),
               &"fa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f"
                    .from_hex()
                    .unwrap()
                    [..]);
}

#[test]
fn should_extract_pbkdf2_based_kdf_private_key() {
    let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");

    let key = json::decode::<emerald::KeyFile>(&file_content(path)).unwrap();

    assert!(key.extract_key("_").is_err());
    assert_eq!(&key.extract_key("1234567890").unwrap(),
               &"00b413b37c71bfb92719d16e28d7329dea5befa0d0b8190742f89e55617991cf"
                    .from_hex()
                    .unwrap()
                    [..]);
}

#[test]
fn should_work_with_keyfile_with_address() {
    let path = keyfile_path("UTC--2017-03-17T10-52-08.\
                             229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");

    let exp = emerald::KeyFile {
        uuid: Uuid::from_str("f7ab2bfa-e336-4f45-a31f-beb3dd0689f3").unwrap(),
        address: Some("0x0047201aed0b69875b24b614dda0270bcd9f11cc"
                          .parse()
                          .unwrap()),
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
        keccak256_mac: arr!(&"9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5"
                                 .from_hex()
                                 .unwrap(),
                            KECCAK256_BYTES),
        cipher: Cipher::default(),
        cipher_text: "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1"
            .from_hex()
            .unwrap(),
        cipher_iv: arr!(&"9df1649dd1c50f2153917e3b9e7164e9".from_hex().unwrap(),
                        CIPHER_IV_BYTES),
    };

    // just first encoding
    let key = json::decode::<emerald::KeyFile>(&file_content(path)).unwrap();

    // verify encoding & decoding full cycle logic
    let key = json::decode::<emerald::KeyFile>(&json::encode(&key).unwrap()).unwrap();

    assert_eq!(key, exp);
    assert_eq!(key.address, exp.address);
    assert_eq!(key.dk_length, exp.dk_length);
    assert_eq!(key.kdf, exp.kdf);
    assert_eq!(key.kdf_salt, exp.kdf_salt);
    assert_eq!(key.keccak256_mac, exp.keccak256_mac);
    assert_eq!(key.cipher_text, exp.cipher_text);
    assert_eq!(key.cipher_iv, exp.cipher_iv);
}

#[test]
fn should_work_with_keyfile_without_address() {
    let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");

    let exp = emerald::KeyFile {
        uuid: Uuid::from_str("37e0d14f-7269-7ca0-4419-d7b13abfeea9").unwrap(),
        address: None,
        dk_length: 32,
        kdf: Kdf::Pbkdf2 {
            prf: Prf::default(),
            c: 10240,
        },
        kdf_salt: arr!(&"095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b"
                            .from_hex()
                            .unwrap(),
                       KDF_SALT_BYTES),
        keccak256_mac: arr!(&"83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63"
                                 .from_hex()
                                 .unwrap(),
                            KECCAK256_BYTES),
        cipher: Cipher::default(),
        cipher_text: "9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126"
            .from_hex()
            .unwrap(),
        cipher_iv: arr!(&"58d54158c3e27131b0a0f2b91201aedc".from_hex().unwrap(),
                        CIPHER_IV_BYTES),
    };

    // just first encoding
    let key = json::decode::<emerald::KeyFile>(&file_content(path)).unwrap();

    // verify encoding & decoding full cycle logic
    let key = json::decode::<emerald::KeyFile>(&json::encode(&key).unwrap()).unwrap();

    assert_eq!(key, exp);
    assert_eq!(key.address, exp.address);
    assert_eq!(key.dk_length, exp.dk_length);
    assert_eq!(key.kdf, exp.kdf);
    assert_eq!(key.kdf_salt, exp.kdf_salt);
    assert_eq!(key.keccak256_mac, exp.keccak256_mac);
    assert_eq!(key.cipher_text, exp.cipher_text);
    assert_eq!(key.cipher_iv, exp.cipher_iv);
}

#[test]
fn should_find_available_addresses() {
    assert!(emerald::address_exists(&keystore_path(),
                                    &"0x0047201aed0b69875b24b614dda0270bcd9f11cc"
                                         .parse::<emerald::Address>()
                                         .unwrap()));
}

#[test]
fn should_ignore_unavailable_addresses() {
    assert!(!emerald::address_exists(&keystore_path(),
                                     &"0x3f4e0668c20e100d7c2a27d4b177ac65b2875d26"
                                          .parse::<emerald::Address>()
                                          .unwrap()));
}

fn file_content<P: AsRef<Path>>(path: P) -> String {
    let mut text = String::new();

    fs::File::open(path)
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

    buf.push("tests/keystore");

    buf
}
