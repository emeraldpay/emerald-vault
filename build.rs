use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=EMRLD_TEST");
    if let Ok(v) = env::var("EMRLD_TEST") {
        println!("cargo:rustc-cfg=integration_test");
        for c in v.split(",") {
            println!("cargo:rustc-cfg=test_{}", c);
        }
    }
}
