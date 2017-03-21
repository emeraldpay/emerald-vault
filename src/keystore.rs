use regex::Regex;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// if we have specified address in out keystore return true, and false otherwise
pub fn address_exists<P: AsRef<Path>>(path: P, addr: &str) -> bool {
    let addr = &addr.to_owned()[2..]; /* cut '0x' prefix */

    let entries = fs::read_dir(path).expect("Expect to read a directory content");

    for entry in entries {
        let path = entry.expect("Expect to extract filesystem entry").path();

        if path.is_dir() {
            continue;
        }

        let mut file = File::open(path).expect("Expect to open a file");
        let mut text = String::new();

        if file.read_to_string(&mut text).is_err() {
            continue;
        }

        match extract_address(&text) {
            Some(a) if a == addr => return true,
            _ => continue,
        }
    }

    false
}

fn extract_address(text: &str) -> Option<&str> {
    lazy_static! {
        static ref ADDR_RE: Regex = Regex::new(r#"address.+([a-fA-F0-9]{40})"#).unwrap();
    }

    ADDR_RE.captures(text).and_then(|gr| gr.get(1)).map(|m| m.as_str())
}

#[cfg(test)]
mod tests {
    use super::extract_address;

    #[test]
    fn should_extract_address() {
        assert_eq!(extract_address(r#"address: '008aeeda4d805471df9b2a5b0f38a0c3bcba786b',"#),
                   Some("008aeeda4d805471df9b2a5b0f38a0c3bcba786b"));
        assert_eq!(extract_address(r#"  "address": "0047201aed0b69875b24b614dda0270bcd9f11cc","#),
                   Some("0047201aed0b69875b24b614dda0270bcd9f11cc"));
        assert_eq!(extract_address(r#"  },
                                      "address": "3f4e0668c20e100d7c2a27d4b177ac65b2875d26",
                                      "name": "",
                                      "meta": "{}"
                                    }"#),
                   Some("3f4e0668c20e100d7c2a27d4b177ac65b2875d26"));
    }

    #[test]
    fn should_ignore_empty() {
        assert_eq!(extract_address(""), None);
    }

    #[test]
    fn should_ignore_pointless() {
        assert_eq!(extract_address(r#""version": 3"#), None);
    }
}
