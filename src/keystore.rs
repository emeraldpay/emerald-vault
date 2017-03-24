use address::Address;
use regex::Regex;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// If we have specified address in out keystore return `true`, `false` otherwise
pub fn address_exists<P: AsRef<Path>>(path: P, addr: &Address) -> bool {
    let entries = fs::read_dir(path).expect("Expect to read a keystore directory content");

    for entry in entries {
        let path = entry.expect("Expect keystore directory entry").path();

        if path.is_dir() {
            continue;
        }

        let mut file = File::open(path).expect("Expect to open a keystore file");
        let mut text = String::new();

        if file.read_to_string(&mut text).is_err() {
            continue;
        }

        match try_extract_address(&text) {
            Some(a) if a == *addr => return true,
            _ => continue,
        }
    }

    false
}

/// Try to extract `Address` from JSON formatted text
pub fn try_extract_address(text: &str) -> Option<Address> {
    lazy_static! {
        static ref ADDR_RE: Regex = Regex::new(r#"address.+([a-fA-F0-9]{40})"#).unwrap();
    }

    ADDR_RE.captures(text)
        .and_then(|gr| gr.get(1))
        .map(|m| format!("0x{}", m.as_str()).parse().unwrap())
}

#[cfg(test)]
mod tests {
    use super::try_extract_address;
    use address::Address;

    #[test]
    fn should_extract_address() {
        assert_eq!(try_extract_address(r#"address: '008aeeda4d805471df9b2a5b0f38a0c3bcba786b',"#),
                   Some("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b".parse::<Address>().unwrap()));

        assert_eq!(try_extract_address(r#""address": "0047201aed0b69875b24b614dda0270bcd9f11cc","#),
                   Some("0x0047201aed0b69875b24b614dda0270bcd9f11cc".parse::<Address>().unwrap()));

        assert_eq!(try_extract_address(r#"  },
                                         "address": "3f4e0668c20e100d7c2a27d4b177ac65b2875d26",
                                         "name": "",
                                         "meta": "{}"
                                       }"#),
                   Some("0x3f4e0668c20e100d7c2a27d4b177ac65b2875d26".parse::<Address>().unwrap()));
    }

    #[test]
    fn should_ignore_pointless() {
        assert_eq!(try_extract_address(r#""version": 3"#), None);
    }

    #[test]
    fn should_ignore_empty() {
        assert_eq!(try_extract_address(""), None);
    }
}
