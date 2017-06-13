extern crate emerald;

extern crate serde;
extern crate serde_json;
extern crate tempdir;

use self::serde_json::Value;
use emerald::contract::{ContractError, Contracts};
use std::path::PathBuf;
use tempdir::TempDir;

const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

#[test]
fn should_see_all_contracts() {
    let c = Contracts::new(contracts_path());
    let act = c.list();
    assert_eq!(act.len(), 1)
}

#[test]
fn should_add_contract() {
    let tmp_dir = TempDir::new("emerald").unwrap();
    let c = Contracts::new(tmp_dir.into_path());
    let act = c.list();
    assert_eq!(act.len(), 0);

    let json = serde_json::from_str::<Value>("{\"version\": \"1.0\", \
                                              \"address\":\
                                              \"0x085fb4f24031eaedbc2b611aa528f22343eb52db\"}")
        .unwrap();
    c.add(&json).ok();
    let act = c.list();
    assert_eq!(act.len(), 1);
}

#[test]
fn invalidate_contract_wo_addr() {
    let json = serde_json::from_str::<Value>("{\"version\": \"1.0\"}").unwrap();
    let c = Contracts::new(contracts_path());
    match c.validate(&json) {
        Err(ContractError::InvalidContract) => {}
        Err(_) => panic!("Should be InvalidContract"),
        Ok(_) => panic!("Should fail"),
    }
}

fn contracts_path() -> PathBuf {
    let mut buf = PathBuf::from(PRJ_DIR.expect("Expect project directory"));
    buf.push("tests/contracts");
    buf
}
