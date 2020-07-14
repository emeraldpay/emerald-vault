extern crate emerald_vault as emerald;
extern crate rand;
extern crate tempdir;
extern crate uuid;
#[macro_use]
extern crate bencher;

use crate::{
    emerald::{
        structs::{
            crypto::Encrypted,
            pk::PrivateKeyHolder,
        },
        convert::json::keyfile::{EthereumJsonV3File},
    }
};

use bencher::Bencher;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tempdir::TempDir;
use std::convert::TryFrom;
use rand::rngs::OsRng;

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

    b.iter(|| pk.decrypt("1234567890"));
}

fn bench_decrypt_pbkdf2(b: &mut Bencher) {
    let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");
    let keyfile = EthereumJsonV3File::try_from(file_content(path)).unwrap();
    let pk = PrivateKeyHolder::try_from(&keyfile).unwrap();

    b.iter(|| pk.decrypt("1234567890"));
}

fn bench_encrypt_message(b: &mut Bencher) {
    b.iter(|| Encrypted::encrypt("test".as_bytes().to_vec(), "1234567890"));
}

benchmark_group!(
    benches,
    bench_decrypt_scrypt,
    bench_decrypt_pbkdf2,
    bench_encrypt_message,
);
benchmark_main!(benches);
