extern crate emerald_vault as emerald;
extern crate rand;
extern crate tempdir;
extern crate uuid;
#[macro_use]
extern crate bencher;

use crate::emerald::{
    convert::json::keyfile::EthereumJsonV3File,
    structs::{crypto::Encrypted, pk::PrivateKeyHolder},
};

use bencher::Bencher;
use std::{
    convert::TryFrom,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use std::str::FromStr;
use hdpath::StandardHDPath;
use tempdir::TempDir;
use emerald::crypto::kdf::KeyDerive;
use emerald::mnemonic::{Language, Mnemonic};
use emerald::structs::crypto::{Argon2, GlobalKey};
use emerald::structs::seed::SeedSource;

const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

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

fn bench_decrypt_scrypt(b: &mut Bencher) {
    let path =
        keyfile_path("UTC--2017-03-17T10-52-08.229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");
    let keyfile = EthereumJsonV3File::try_from(file_content(path)).unwrap();
    let pk = PrivateKeyHolder::try_from(&keyfile).unwrap();

    b.iter(|| pk.decrypt("1234567890".as_bytes(), None));
}

fn bench_decrypt_argon_global(b: &mut Bencher) {
    b.iter(|| {
        let kdf = Argon2::new_global(hex::decode("0102030405060708").unwrap());
        kdf.derive("1234567890".as_bytes()).expect("Failed to derive")
    });
}

fn bench_decrypt_argon_subkey(b: &mut Bencher) {
    b.iter(|| {
        let kdf = Argon2::new_subkey(hex::decode("0102030405060708").unwrap());
        kdf.derive("1234567890".as_bytes()).expect("Failed to derive")
        // println!("x: {:}", hex::encode(x));
    });
}

fn bench_decrypt_pbkdf2(b: &mut Bencher) {
    let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");
    let keyfile = EthereumJsonV3File::try_from(file_content(path)).unwrap();
    let pk = PrivateKeyHolder::try_from(&keyfile).unwrap();

    b.iter(|| pk.decrypt("1234567890".as_bytes(), None));
}

fn bench_encrypt_message(b: &mut Bencher) {
    b.iter(|| Encrypted::encrypt("test".as_bytes().to_vec(), "1234567890".as_bytes(), None));
}

fn bench_seed_access(b: &mut Bencher) {
    let password = "testtesttest";
    let global = GlobalKey::generate(password.as_bytes()).expect("Global key not generated");
    let phrase = Mnemonic::try_from(
        Language::English,
        "quote ivory blast onion below kangaroo tonight spread awkward decide farm gun exact wood brown",
    ).unwrap();
    let seed = SeedSource::Bytes(
        Encrypted::encrypt(
            phrase.seed(None),
            password.as_bytes(),
            Some(global.clone()),
        ).unwrap()
    );

    b.iter(|| {
        seed.get_pk(
            // use _nokey_ to decrypt the seed
            Some(password.to_string()),
            // Global Key is not used, threfore None
            &Some(global.clone()),
            // ....
            &StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap(),
        ).expect("Failed to get PK");
    });
}

benchmark_group!(
    benches,
    bench_decrypt_scrypt,
    bench_decrypt_pbkdf2,
    bench_encrypt_message,
    bench_seed_access,
    bench_decrypt_argon_global,
    bench_decrypt_argon_subkey,
);
benchmark_main!(benches);
