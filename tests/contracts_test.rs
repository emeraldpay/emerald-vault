extern crate emerald;

use emerald::contracts::Contracts;
use std::path::PathBuf;

const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

#[test]
fn should_see_all_contracts() {
    let c = Contracts::new(contracts_path());
    let act = c.list();
    assert_eq!(act.len(), 1)
}


fn contracts_path() -> String {
    let mut buf = PathBuf::from(PRJ_DIR.expect("Expect project directory"));
    buf.push("tests/contracts");
    buf.to_str().unwrap().to_string()
}
