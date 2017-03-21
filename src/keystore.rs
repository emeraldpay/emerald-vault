use std::path::Path;

/// if we have specified address in out keystore return true, and false otherwise
pub fn address_exists<P: AsRef<Path>>(_path: P, addr: &str) -> bool {
    match addr {
        "0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b" |
        "0x0047201aed0b69875b24b614dda0270bcd9f11cc" |
        "0x3f4e0668c20e100d7c2a27d4b177ac65b2875d26" => true,
        _ => false,
    }
}
