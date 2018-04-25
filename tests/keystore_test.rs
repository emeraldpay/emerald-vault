extern crate emerald_rs as emerald;
extern crate hex;
extern crate rustc_serialize;
extern crate tempdir;
extern crate uuid;

use emerald::keystore::{Cipher, CoreCrypto, CryptoType, HdwalletCrypto, Iv, Kdf, KdfDepthLevel,
                        KeyFile, Mac, Prf, Salt, CIPHER_IV_BYTES, KDF_SALT_BYTES};
use emerald::storage::{DbStorage, FsStorage, KeyfileStorage};
use emerald::{Address, KECCAK256_BYTES};
use hex::FromHex;
use rustc_serialize::json;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempdir::TempDir;
use uuid::Uuid;

const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

macro_rules! arr {
    ($bytes:expr, $num:expr) => {{
        let mut arr = [0u8; $num];
        arr.copy_from_slice($bytes);
        arr
    }};
}

pub fn temp_dir() -> PathBuf {
    let dir = TempDir::new("emerald").unwrap();
    File::create(dir.path()).ok();
    dir.into_path()
}

pub fn file_content<P: AsRef<Path>>(path: P) -> String {
    let mut text = String::new();

    File::open(path)
        .expect("Expect read file content")
        .read_to_string(&mut text)
        .ok();

    text
}

pub fn keyfile_path(name: &str) -> PathBuf {
    let mut path = keystore_path();
    path.push(name);
    path
}

pub fn keystore_path() -> PathBuf {
    let mut buf = PathBuf::from(PRJ_DIR.expect("Expect project directory"));
    buf.push("tests/keystore/serialize");
    buf
}

#[test]
fn should_decrypt_private_key_protected_by_scrypt() {
    let path =
        keyfile_path("UTC--2017-03-17T10-52-08.229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");

    let keyfile = KeyFile::decode(&file_content(path)).unwrap();

    assert!(keyfile.decrypt_key("_").is_err());
    assert_eq!(
        keyfile.decrypt_key("1234567890").unwrap().to_string(),
        "0xfa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f"
    );
}

#[test]
fn should_decrypt_private_key_protected_by_pbkdf2() {
    let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");

    let keyfile = KeyFile::decode(&file_content(path)).unwrap();

    assert!(keyfile.decrypt_key("_").is_err());
    assert_eq!(
        keyfile.decrypt_key("1234567890").unwrap().to_string(),
        "0x00b413b37c71bfb92719d16e28d7329dea5befa0d0b8190742f89e55617991cf"
    );
}

#[test]
fn should_decode_keyfile_without_address() {
    let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");

    let mut crypto = CoreCrypto::default();
    crypto.kdfparams_dklen = 32;
    crypto.kdf = Kdf::Pbkdf2 {
        prf: Prf::default(),
        c: 10240,
    };
    crypto.kdfparams_salt = Salt::from(arr!(
        &Vec::from_hex("095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b",)
            .unwrap(),
        KDF_SALT_BYTES
    ));
    crypto.cipher = Cipher::default();
    crypto.cipher_text =
        Vec::from_hex("9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126").unwrap();

    crypto.cipher_params.iv = Iv::from(arr!(
        &Vec::from_hex("58d54158c3e27131b0a0f2b91201aedc").unwrap(),
        CIPHER_IV_BYTES
    ));

    crypto.mac = Mac::from(arr!(
        &Vec::from_hex("83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63",)
            .unwrap(),
        KECCAK256_BYTES
    ));

    let exp = KeyFile {
        visible: None,
        name: Some("".to_string()),
        description: None,
        address: Address::from_str("0x4c4cfc6470a1dc26916585ef03dfec42deb936ff").unwrap(),
        uuid: Uuid::from_str("37e0d14f-7269-7ca0-4419-d7b13abfeea9").unwrap(),
        crypto: CryptoType::Core(crypto),
    };

    // just first encoding
    let key = KeyFile::decode(&file_content(path)).unwrap();

    // verify encoding & decoding full cycle logic
    let key = KeyFile::decode(&json::encode(&key).unwrap()).unwrap();

    if let CryptoType::Core(ref exp_core) = exp.crypto {
        if let CryptoType::Core(ref recv_core) = key.crypto {
            assert_eq!(key, exp);
            assert_eq!(key.visible, exp.visible);
            assert_eq!(recv_core.kdfparams_dklen, exp_core.kdfparams_dklen);
            assert_eq!(recv_core.kdf, exp_core.kdf);
            assert_eq!(recv_core.kdfparams_salt, exp_core.kdfparams_salt);
            assert_eq!(recv_core.cipher_text, exp_core.cipher_text);
            assert_eq!(recv_core.cipher_params.iv, exp_core.cipher_params.iv);
            assert_eq!(recv_core.mac, exp_core.mac);
        } else {
            assert!(false, "Invalid Crypto type")
        }
    }
}

#[test]
fn should_decode_keyfile_with_address() {
    let path =
        keyfile_path("UTC--2017-03-17T10-52-08.229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");

    let mut crypto = CoreCrypto::default();
    crypto.kdfparams_dklen = 32;
    crypto.kdf = Kdf::Scrypt {
        n: 1024,
        r: 8,
        p: 1,
    };
    crypto.kdfparams_salt = Salt::from(arr!(
        &Vec::from_hex("fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4",)
            .unwrap(),
        KDF_SALT_BYTES
    ));
    crypto.cipher = Cipher::default();
    crypto.cipher_text =
        Vec::from_hex("c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1").unwrap();

    crypto.cipher_params.iv = Iv::from(arr!(
        &Vec::from_hex("9df1649dd1c50f2153917e3b9e7164e9").unwrap(),
        CIPHER_IV_BYTES
    ));

    crypto.mac = Mac::from(arr!(
        &Vec::from_hex("9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5",)
            .unwrap(),
        KECCAK256_BYTES
    ));

    let exp = KeyFile {
        visible: None,
        name: None,
        description: None,
        address: Address::from_str("0x0047201aed0b69875b24b614dda0270bcd9f11cc").unwrap(),
        uuid: Uuid::from_str("f7ab2bfa-e336-4f45-a31f-beb3dd0689f3").unwrap(),
        crypto: CryptoType::Core(crypto),
    };

    // just first encoding
    let key = KeyFile::decode(&file_content(path)).unwrap();

    // verify encoding & decoding full cycle logic
    let key = KeyFile::decode(&json::encode(&key).unwrap()).unwrap();

    if let CryptoType::Core(ref exp_core) = exp.crypto {
        if let CryptoType::Core(ref recv_core) = key.crypto {
            assert_eq!(key, exp);
            assert_eq!(key.visible, exp.visible);
            assert_eq!(recv_core.kdfparams_dklen, exp_core.kdfparams_dklen);
            assert_eq!(recv_core.kdf, exp_core.kdf);
            assert_eq!(recv_core.kdfparams_salt, exp_core.kdfparams_salt);
            assert_eq!(recv_core.cipher_text, exp_core.cipher_text);
            assert_eq!(recv_core.cipher_params.iv, exp_core.cipher_params.iv);
            assert_eq!(recv_core.mac, exp_core.mac);
        } else {
            assert!(false, "Invalid Crypto type")
        }
    }
}

#[test]
fn should_decode_hd_wallet_keyfile() {
    let path = keyfile_path("UTC--2017-05-30T06-16-46Z--a928d7c2-b37b-464c-a70b-b9979d59fac5");

    let mut crypto = HdwalletCrypto::default();
    crypto.cipher = "hardware".to_string();
    crypto.hardware = "ledger-nano-s:v1".to_string();
    crypto.hd_path = "44'/61'/0'/0/0".to_string();

    let exp = KeyFile {
        visible: None,
        name: None,
        description: None,
        address: Address::from_str("01234567890abcdef1234567890abcdef1234567").unwrap(),
        uuid: Uuid::from_str("a928d7c2-b37b-464c-a70b-b9979d59fac5").unwrap(),
        crypto: CryptoType::HdWallet(crypto),
    };

    // just first encoding
    let key = KeyFile::decode(&file_content(path)).unwrap();

    // verify encoding & decoding full cycle logic
    let key = KeyFile::decode(&json::encode(&key).unwrap()).unwrap();

    if let CryptoType::HdWallet(ref exp_hd) = exp.crypto {
        if let CryptoType::HdWallet(ref recv_hd) = key.crypto {
            assert_eq!(key, exp);
            assert_eq!(key.visible, exp.visible);
            assert_eq!(recv_hd.cipher, exp_hd.cipher);
            assert_eq!(recv_hd.hardware, exp_hd.hardware);
            assert_eq!(recv_hd.hd_path, exp_hd.hd_path);
        } else {
            assert!(false, "Invalid Crypto type")
        }
    }
}

#[test]
//TODO:1 remove condition after fix for `scrypt` on Windows
#[cfg(not(target_os = "windows"))]
fn should_use_security_level() {
    let sec = KdfDepthLevel::Normal;
    let kf = KeyFile::new("1234567890", &sec, None, None).unwrap();
    if let CryptoType::Core(ref core) = kf.crypto {
        assert_eq!(core.kdf, Kdf::from(sec));
    } else {
        assert!(false, "Invalid Crypto type")
    }

    let sec = KdfDepthLevel::High;
    let kf = KeyFile::new("1234567890", &sec, Some("s".to_string()), None).unwrap();
    if let CryptoType::Core(ref core) = kf.crypto {
        assert_eq!(core.kdf, Kdf::from(sec));
    } else {
        assert!(false, "Invalid Crypto type")
    }
}

#[test]
fn should_flush_to_file() {
    let kf = KeyFile::new("1234567890", &KdfDepthLevel::Normal, None, None).unwrap();

    let storage = FsStorage::new(&temp_dir().as_path());

    assert!(storage.put(&kf).is_ok());
}

#[test]
fn should_search_by_address_filesystem() {
    let addr = "0xc0de379b51d582e1600c76dd1efee8ed024b844a"
        .parse::<Address>()
        .unwrap();

    let storage = FsStorage::new(&keystore_path());
    let (_, kf) = storage.search_by_address(&addr).unwrap();

    assert_eq!(
        kf.uuid,
        "a928d7c2-b37b-464c-a70b-b9979d59fac4".parse().unwrap()
    );
}

#[test]
fn should_search_by_address_db() {
    let addr = "0xc0de379b51d582e1600c76dd1efee8ed024b844a"
        .parse::<Address>()
        .unwrap();

    let path = keyfile_path("UTC--2017-05-30T06-16-46Z--a928d7c2-b37b-464c-a70b-b9979d59fac4");
    let key = KeyFile::decode(&file_content(path)).unwrap();

    let storage = DbStorage::new(temp_dir().as_path()).unwrap();
    storage.put(&key).unwrap();

    let (_, kf) = storage.search_by_address(&addr).unwrap();

    assert_eq!(
        kf.uuid,
        "a928d7c2-b37b-464c-a70b-b9979d59fac4".parse().unwrap()
    );
}

#[test]
fn should_update_existing_addresses() {
    let path = keyfile_path("UTC--2017-05-30T06-16-46Z--a928d7c2-b37b-464c-a70b-b9979d59fac4");
    let mut key = KeyFile::decode(&file_content(path)).unwrap();

    let storage = DbStorage::new(temp_dir().as_path()).unwrap();
    assert!(key.name.is_none());
    storage.put(&key).unwrap();

    let updated_name = Some("updated name".to_string());
    key.name = updated_name.clone();
    assert!(storage.put(&key).is_ok());

    let (_, kf) = storage.search_by_address(&key.address).unwrap();
    assert_eq!(kf.name, updated_name)
}
