/*
Copyright 2019 ETCDEV GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
extern crate emerald_rs as emerald;
extern crate serde_json;
extern crate tempdir;

use crate::emerald::storage::{AddressbookError, AddressbookStorage};
use serde_json::Value;
use std::path::PathBuf;
use tempdir::TempDir;

const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

#[test]
fn should_see_all_entries() {
    let a = AddressbookStorage::new(addressbook_path());
    let act = a.list();
    assert_eq!(act.len(), 2)
}

#[test]
fn should_add_entry() {
    let tmp_dir = TempDir::new("emerald").unwrap();
    let a = AddressbookStorage::new(tmp_dir.into_path());
    let act = a.list();
    assert_eq!(act.len(), 0);

    let json = serde_json::from_str::<Value>(
        "{\"address\":\"0x000000000031eaedbc2b611aa528f22343eb52db\", \"name\":\"elaine\", \
         \"description\":\"drug money\"}",
    )
    .unwrap();
    a.add(&json).ok();
    let act = a.list();
    assert_eq!(act.len(), 1);
}

#[test]
fn invalidate_entry_wo_addr() {
    let json = serde_json::from_str::<Value>("{\"name\": \"elaine\"}").unwrap();
    let a = AddressbookStorage::new(addressbook_path());
    match a.validate(&json) {
        Err(AddressbookError::InvalidAddress(ref _str)) => {}
        Err(_) => panic!("Should be InvalidAddress"),
        Ok(_) => panic!("Should fail"),
    }
}

fn addressbook_path() -> PathBuf {
    let mut buf = PathBuf::from(PRJ_DIR.expect("Expect project directory"));
    buf.push("tests/addressbook");
    buf
}
