#![feature(test)]
extern crate emerald_core;
extern crate rand;
extern crate rustc_serialize;
extern crate tempdir;
extern crate test;
extern crate uuid;

use emerald_core::keccak256;
use emerald_core::keystore::{os_random, Kdf, KdfDepthLevel, KeyFile};
use emerald_core::PrivateKey;
use rustc_serialize::json;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tempdir::TempDir;
use test::Bencher;

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

#[bench]
fn bench_decrypt_scrypt(b: &mut Bencher) {
    let path =
        keyfile_path("UTC--2017-03-17T10-52-08.229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");

    let keyfile = KeyFile::decode(file_content(path)).unwrap();

    b.iter(|| keyfile.decrypt_key("12345e67890"));
}

#[bench]
fn bench_decrypt_pbkdf2(b: &mut Bencher) {
    let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");
    let keyfile = KeyFile::decode(file_content(path)).unwrap();

    b.iter(|| keyfile.decrypt_key("1234567890"));
}

#[bench]
fn bench_encrypt_scrypt(b: &mut Bencher) {
    let sec = KdfDepthLevel::Ultra;
    b.iter(|| KeyFile::new("1234567890", &sec, None, None));
}

#[bench]
fn bench_encrypt_pbkdf2(b: &mut Bencher) {
    let mut rng = os_random();
    let pk = PrivateKey::gen_custom(&mut rng);

    b.iter(|| KeyFile::new_custom(pk, "1234567890", Kdf::from(10240), &mut rng, None, None));
}

#[bench]
fn bench_small_sha3(b: &mut Bencher) {
    b.iter(|| keccak256(&[b'-'; 16]));
}

#[bench]
fn bench_big_sha3(b: &mut Bencher) {
    b.iter(|| keccak256(&[b'-'; 1024]));
}
