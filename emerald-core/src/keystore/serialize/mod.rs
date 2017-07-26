//! # Serialize keystore files (UTC / JSON) encrypted with a passphrase module

mod address;
#[macro_use]
mod byte_array;
mod crypto;
mod error;

use self::address::try_extract_address;
pub use self::crypto::{CoreCrypto, Iv, Mac, Salt, decode_str};
use self::error::Error;
use super::{CIPHER_IV_BYTES, Cipher, CryptoType, KDF_SALT_BYTES, Kdf, KeyFile};
use super::HdwalletCrypto;
use super::core::{self, Address};
use super::util;
use rustc_serialize::{Encodable, Encoder, json};
use std::fs::{self, File, read_dir};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Keystore file current version used for serializing
pub const CURRENT_VERSION: u8 = 3;

/// Supported keystore file versions (only current V3 now)
pub const SUPPORTED_VERSIONS: &'static [u8] = &[CURRENT_VERSION];

/// A serializable keystore file (UTC / JSON format)
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
pub struct SerializableKeyFileCore {
    version: u8,
    id: Uuid,
    address: Address,
    name: Option<String>,
    description: Option<String>,
    visible: Option<bool>,
    crypto: CoreCrypto,
}

impl SerializableKeyFileCore {
    fn try_from(kf: KeyFile) -> Result<Self, Error> {
        let cr = CoreCrypto::try_from(kf.clone())?;

        Ok(SerializableKeyFileCore {
            version: CURRENT_VERSION,
            id: kf.uuid,
            address: kf.address,
            name: kf.name.clone(),
            description: kf.description.clone(),
            visible: kf.visible,
            crypto: cr,
        })
    }
}

impl Into<KeyFile> for SerializableKeyFileCore {
    fn into(self) -> KeyFile {
        KeyFile {
            name: self.name,
            description: self.description,
            address: self.address,
            visible: self.visible,
            uuid: self.id,
            crypto: CryptoType::Core(self.crypto),
        }
    }
}

/// A serializable keystore file (UTC / JSON format)
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
pub struct SerializableKeyFileHD {
    version: u8,
    id: Uuid,
    address: Address,
    name: Option<String>,
    description: Option<String>,
    visible: Option<bool>,
    crypto: HdwalletCrypto,
}

impl SerializableKeyFileHD {
    fn try_from(kf: KeyFile) -> Result<Self, Error> {
        let cr = HdwalletCrypto::try_from(kf.clone())?;

        Ok(SerializableKeyFileHD {
            version: CURRENT_VERSION,
            id: kf.uuid,
            address: kf.address,
            name: kf.name.clone(),
            description: kf.description.clone(),
            visible: kf.visible,
            crypto: cr,
        })
    }
}

impl Into<KeyFile> for SerializableKeyFileHD {
    fn into(self) -> KeyFile {
        KeyFile {
            name: self.name,
            description: self.description,
            address: self.address,
            visible: self.visible,
            uuid: self.id,
            crypto: CryptoType::HdWallet(self.crypto),
        }
    }
}

impl KeyFile {
    /// Decode `Keyfile` from JSON
    /// Handles different variants of `crypto` section
    ///
    pub fn decode(f: String) -> Result<KeyFile, Error> {
        let buf1 = f.clone();
        let buf2 = f.clone();
        let mut ver = 0;

        let kf = json::decode::<SerializableKeyFileCore>(&buf1)
            .and_then(|core| {
                ver = core.version;
                Ok(core.into())
            })
            .or_else(|_| {
                json::decode::<SerializableKeyFileHD>(&buf2).and_then(|hd| {
                    ver = hd.version;
                    Ok(hd.into())
                })
            })
            .map_err(|e| Error::from(e))?;

        if !SUPPORTED_VERSIONS.contains(&ver) {
            return Err(Error::UnsupportedVersion(ver));
        }

        Ok(kf)
    }

    /// Serializes into JSON file with the name format `UTC--<timestamp>Z--<uuid>`
    ///
    /// # Arguments
    ///
    /// * `dir` - path to destination directory
    /// * `addr` - a public address (optional)
    ///
    pub fn flush<P: AsRef<Path>>(&self, dir: P, filename: Option<&str>) -> Result<(), Error> {
        let tmp;
        let name = match filename {
            Some(n) => n,
            None => {
                tmp = generate_filename(&self.uuid.to_string());
                &tmp
            }
        };
        let path = dir.as_ref().join(name);

        Ok(write(self, path)?)
    }

    /// Search of `KeyFile` by specified `Address`
    /// Returns set of filepath and `Keyfile`
    ///
    /// # Arguments
    ///
    /// * `path` - path with keystore files
    ///
    pub fn search_by_address<P: AsRef<Path>>(
        addr: &Address,
        path: P,
    ) -> Result<(PathBuf, KeyFile), Error> {
        let entries = fs::read_dir(path)?;

        for entry in entries {
            let path = entry?.path();

            if path.is_dir() {
                continue;
            }

            let mut file = fs::File::open(&path)?;
            let mut content = String::new();

            if file.read_to_string(&mut content).is_err() {
                continue;
            }

            match try_extract_address(&content) {
                Some(a) if a == *addr => {
                    let kf = KeyFile::decode(content)?;
                    return Ok((path.to_owned(), kf));
                }
                _ => continue,
            }
        }

        Err(Error::NotFound)
    }
}

impl Encodable for KeyFile {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        match SerializableKeyFileCore::try_from(self.clone()) {
            Ok(sf) => sf.encode(s),
            Err(_) => {
                match SerializableKeyFileHD::try_from(self.clone()) {
                    Ok(sf) => sf.encode(s),
                    Err(_) => Ok(()),
                }
            }

        }
    }
}


/// Writes out `Keyfile` into disk accordingly to `p` path
/// Try to match one wvariant of KeyFile:
///     `..Core` - for normal `Keyfile` created as JSON safe storage
///     `..HD` - for usage with HD wallets
///
/// #Arguments:
/// kf - `Keyfile` to be written
/// p - destination route (path + filename)
///
pub fn write<P: AsRef<Path>>(kf: &KeyFile, p: P) -> Result<(), Error> {
    let json = match SerializableKeyFileCore::try_from(kf.clone()) {
        Ok(sf) => json::encode(&sf)?,
        Err(_) => {
            match SerializableKeyFileHD::try_from(kf.clone()) {
                Ok(sf) => json::encode(&sf)?,
                Err(e) => return Err(Error::InvalidCrypto(e.to_string())),
            }
        }
    };

    let mut file = File::create(&p)?;
    file.write_all(json.as_ref()).ok();

    Ok(())
}

/// Lists addresses for `Keystore` files in specified folder.
/// Can include hidden files if flag set.
///
/// # Arguments
///
/// * `path` - target directory
/// * `showHidden` - flag to show hidden `Keystore` files
///
/// # Return:
/// Array of tuples (name, address, description, is_hidden)
///
pub fn list_accounts<P: AsRef<Path>>(
    path: P,
    show_hidden: bool,
) -> Result<Vec<(String, String, String, bool)>, Error> {
    let mut accounts: Vec<(String, String, String, bool)> = vec![];
    for e in read_dir(&path)? {
        if e.is_err() {
            continue;
        }
        let entry = e.unwrap();
        let mut content = String::new();
        if let Ok(mut keyfile) = File::open(entry.path()) {
            if keyfile.read_to_string(&mut content).is_err() {
                continue;
            }

            match KeyFile::decode(content) {
                Ok(kf) => {
                    let mut info = Vec::new();
                    if kf.visible.is_none() || kf.visible.unwrap() || show_hidden {
                        let is_hd = match kf.crypto {
                            CryptoType::Core(_) => false,
                            CryptoType::HdWallet(_) => true,
                        };
                        match kf.name {
                            Some(name) => info.push(name),
                            None => info.push("".to_string()),
                        }

                        match kf.description {
                            Some(desc) => info.push(desc),
                            None => info.push("".to_string()),
                        }
                        accounts.push((
                            info[0].clone(),
                            kf.address.to_string(),
                            info[1].clone(),
                            is_hd,
                        ));
                    }
                }
                Err(_) => info!("Invalid keystore file format for: {:?}", entry.file_name()),
            }
        }
    }

    Ok(accounts)
}

/// Hides account for given address from being listed
///
/// #Arguments
/// addr - target address
/// path - folder with keystore files
///
pub fn hide<P: AsRef<Path>>(addr: &Address, path: P) -> Result<bool, Error> {
    let (p, mut kf) = KeyFile::search_by_address(addr, &path)?;

    kf.visible = Some(false);
    write(&kf, &p)?;

    Ok(true)
}

/// Unhides account for given address from being listed
///
/// #Arguments
/// addr - target address
/// path - folder with keystore files
///
pub fn unhide<P: AsRef<Path>>(addr: &Address, path: P) -> Result<bool, Error> {
    let (p, mut kf) = KeyFile::search_by_address(addr, &path)?;

    kf.visible = Some(true);
    write(&kf, &p)?;

    Ok(true)
}


/// Creates filename for keystore file in format:
/// `UTC--yyy-mm-ddThh-mm-ssZ--uuid`
///
/// # Arguments
///
/// * `uuid` - UUID for keyfile
///
fn generate_filename(uuid: &str) -> String {
    format!("UTC--{}Z--{}", &util::timestamp(), &uuid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_catch_unsupported_keyfile_version() {
        let str = r#"{
          "version": 2,
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(KeyFile::decode(str.to_string()).is_err());
    }

    #[test]
    fn should_catch_keyfile_version_malformed() {
        let str = r#"{
          "version": "x",
          "id": "9bec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(KeyFile::decode(str.to_string()).is_err());
    }

    #[test]
    fn should_catch_keyfile_uuid_malformed() {
        let str = r#"{
          "version": 3,
          "id": "__ec4728-37f9-4444-9990-2ba70ee038e9"
        }"#;

        assert!(KeyFile::decode(str.to_string()).is_err());
    }

    #[test]
    fn should_catch_absent_keyfile_uuid() {
        let str = r#"{"version": 3}"#;

        assert!(KeyFile::decode(str.to_string()).is_err());
    }

    #[test]
    fn should_generate_filename() {
        let re = Regex::new(r"^UTC--\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z--*").unwrap();

        assert!(re.is_match(
            &generate_filename("9bec4728-37f9-4444-9990-2ba70ee038e9"),
        ));
    }
}
