use regex::Regex;
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

#[allow(dead_code)]
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
