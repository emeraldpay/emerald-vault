use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=EMRLD_TEST");
    match env::var("EMRLD_TEST") {
        Ok(v) => {
            println!("cargo:rustc-cfg=integration_test");
            println!("cargo:rustc-cfg={}", v);
        },
        Err(_) => {},
    }
}
