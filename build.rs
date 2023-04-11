use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=EMRLD_TEST");
    match env::var("EMRLD_TEST") {
        Ok(v) => {
            println!("cargo:rustc-cfg=integration_test");
            for c in v.split(",") {
                println!("cargo:rustc-cfg={}", c);
            }
        },
        Err(_) => {},
    }
}
