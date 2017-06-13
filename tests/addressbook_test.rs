extern crate emerald;

extern crate serde;
extern crate serde_json;
extern crate tempdir;

use emerald::addressbook::{Addressbook, AddressbookError};
use serde_json::Value;
use std::path::PathBuf;
use tempdir::TempDir;

const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

#[test]
fn should_see_all_entries() {
    let a = Addressbook::new(addressbook_path());
    let act = a.list();
    assert_eq!(act.len(), 2)
}

#[test]
fn should_add_entry() {
    let tmp_dir = TempDir::new("emerald").unwrap();
    let a = Addressbook::new(tmp_dir.into_path());
    let act = a.list();
    assert_eq!(act.len(), 0);

    let json =
        serde_json::from_str::<Value>("{\"id\":\"0x000000000031eaedbc2b611aa528f22343eb52db\", \
                                       \"name\":\"elaine\", \"description\":\"drug money\"}")
            .unwrap();
    a.add(&json).ok();
    let act = a.list();
    assert_eq!(act.len(), 1);
}

#[test]
fn invalidate_entry_wo_addr() {
    let json = serde_json::from_str::<Value>("{\"name\": \"elaine\"}").unwrap();
    let a = Addressbook::new(addressbook_path());
    match a.validate(&json) {
        Err(AddressbookError::InvalidAddress) => {}
        Err(_) => panic!("Should be InvalidAddress"),
        Ok(_) => panic!("Should fail"),
    }
}

fn addressbook_path() -> PathBuf {
    let mut buf = PathBuf::from(PRJ_DIR.expect("Expect project directory"));
    buf.push("tests/addressbook");
    buf
}
