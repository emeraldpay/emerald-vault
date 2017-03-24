extern crate emerald;

use std::path::PathBuf;

const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

#[test]
fn should_find_available_addresses() {
    assert!(emerald::address_exists(&keystore_path(),
                                    &"0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b"
                                        .parse::<emerald::Address>()
                                        .unwrap()));

    assert!(emerald::address_exists(&keystore_path(),
                                    &"0x0047201aed0b69875b24b614dda0270bcd9f11cc"
                                        .parse::<emerald::Address>()
                                        .unwrap()));

    assert!(emerald::address_exists(&keystore_path(),
                                    &"0x3f4e0668c20e100d7c2a27d4b177ac65b2875d26"
                                        .parse::<emerald::Address>()
                                        .unwrap()));
}

#[test]
fn should_ignore_unavailable_addresses() {
    assert!(!emerald::address_exists(&keystore_path(),
                                     &"0x0e7c045110b8dbf29765047380898919c5cb56f4"
                                         .parse::<emerald::Address>()
                                         .unwrap()));
}

fn keystore_path() -> std::ffi::OsString {
    let mut buf = PathBuf::from(PRJ_DIR.expect("Expect project directory"));

    buf.push("tests/keystore");

    buf.into_os_string()
}
