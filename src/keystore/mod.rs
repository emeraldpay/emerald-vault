//! Keystore files (UTC / JSON) encrypted with a passphrase

mod serialize;

use self::serialize::try_extract_address;
use address::Address;
use std::{cmp, fmt, fs};
use std::io::Read;
use std::path::Path;
use uuid::Uuid;

/// A keystore file corresponds UTC / JSON format (Web3 Secret Storage)
#[derive(Clone, Debug, Eq)]
pub struct KeyFile {
    pub id: Uuid,
    pub address: Option<Address>,
}

impl KeyFile {
    #[allow(dead_code)]
    fn new() -> Self {
        Self::from(Uuid::new_v4())
    }

    #[allow(dead_code)]
    fn with_address(&mut self, addr: &Address) {
        self.address = Some(*addr);
    }
}

impl From<Uuid> for KeyFile {
    fn from(id: Uuid) -> Self {
        KeyFile {
            id: id,
            address: None,
        }
    }
}

impl PartialEq for KeyFile {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl PartialOrd for KeyFile {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyFile {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl fmt::Display for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keystore file: {}", self.id)
    }
}

/// If we have specified address in out keystore return `true`, `false` otherwise
pub fn address_exists<P: AsRef<Path>>(path: P, addr: &Address) -> bool {
    let entries = fs::read_dir(path).expect("Expect to read a keystore directory content");

    for entry in entries {
        let path = entry.expect("Expect keystore directory entry").path();

        if path.is_dir() {
            continue;
        }

        let mut file = fs::File::open(path).expect("Expect to open a keystore file");
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

#[cfg(test)]
mod tests {}
