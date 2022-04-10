/*
Copyright 2019 ETCDEV GmbH
Copyright 2020 EmeraldPay, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//! # Addressbook utils

use crate::{
    convert::error::ConversionError,
    storage::vault::VaultAccess,
    error::VaultError,
    structs::{book::BookmarkDetails, types::HasUuid},
};
use csv::{StringRecord, Writer};
use std::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fs,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use crate::storage::archive::Archive;

const FORMAT: &str = "bookmark/base64";

/// Addressbook Service
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressbookStorage {
    path: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
struct CsvRecord {
    id: String,
    format: String,
    data: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddressBookmark {
    pub id: Uuid,
    pub details: BookmarkDetails,
}

impl HasUuid for AddressBookmark {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl Ord for AddressBookmark {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for AddressBookmark {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<CsvRecord> for AddressBookmark {
    type Error = ConversionError;

    fn try_from(value: CsvRecord) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&value.id)
            .map_err(|_| ConversionError::InvalidFieldValue("id".to_string()))?;
        if FORMAT != value.format {
            return Err(ConversionError::InvalidFieldValue("format".to_string()));
        }
        let data = base64::decode(&value.data)
            .map_err(|_| ConversionError::InvalidFieldValue("data".to_string()))?;
        let details = BookmarkDetails::try_from(data)?;
        let result = AddressBookmark { id, details };
        Ok(result)
    }
}

impl AddressbookStorage {
    pub fn from_path<P>(path: P) -> AddressbookStorage
    where
        P: AsRef<Path>,
    {
        AddressbookStorage {
            path: PathBuf::from(path.as_ref()),
        }
    }

    pub fn get_all(&self) -> Result<Vec<AddressBookmark>, VaultError> {
        let mut result = Vec::new();
        if !&self.path.exists() {
            return Ok(result);
        }
        let mut rdr = csv::ReaderBuilder::default()
            .has_headers(false)
            .from_path(&self.path)?;
        for (i, line) in rdr.records().enumerate() {
            let line = line?;
            if i == 0 && line.len() > 0 && line.get(0) == Some("id") {
                continue;
            }
            let record: CsvRecord = AddressbookStorage::read(line)?;
            let bookmark = AddressBookmark::try_from(record)?;
            result.push(bookmark);
        }
        Ok(result)
    }

    fn read(record: StringRecord) -> Result<CsvRecord, VaultError> {
        if record.len() != 3 {
            return Err(VaultError::UnsupportedDataError(
                "Excessive column".to_string(),
            ));
        }
        let result = CsvRecord {
            id: record.get(0).unwrap().to_string(),
            format: record.get(1).unwrap().to_string(),
            data: record.get(2).unwrap().to_string(),
        };
        Ok(result)
    }

    fn write(wrt: &mut Writer<File>, record: CsvRecord) -> Result<(), VaultError> {
        let mut line = Vec::new();
        line.push(record.id);
        line.push(FORMAT.to_string());
        line.push(record.data);
        wrt.write_record(&line)
            .map_err(|_| VaultError::FilesystemError("CSV record not written".to_string()))
    }
}

impl VaultAccess<AddressBookmark> for AddressbookStorage {
    fn list(&self) -> Result<Vec<Uuid>, VaultError> {
        let ids = self.get_all()?.iter().map(|b| b.id).collect();
        Ok(ids)
    }

    fn get(&self, id: Uuid) -> Result<AddressBookmark, VaultError> {
        let all = self.get_all()?;
        let found = all.iter().find(|b| b.id == id);
        if found.is_none() {
            Err(VaultError::IncorrectIdError)
        } else {
            Ok(found.unwrap().clone())
        }
    }

    fn add(&self, item: AddressBookmark) -> Result<Uuid, VaultError> {
        let id = item.get_id();

        let first_time = !self.path.exists();
        let f = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut wrt = csv::WriterBuilder::new()
            .has_headers(first_time)
            .from_writer(f);

        let data: Vec<u8> = item.details.try_into()?;
        AddressbookStorage::write(
            &mut wrt,
            CsvRecord {
                id: id.to_string(),
                format: FORMAT.to_string(),
                data: base64::encode(&data),
            },
        )?;
        if wrt.flush().is_err() {
            Err(VaultError::FilesystemError("Flush failed".to_string()))
        } else {
            Ok(id)
        }
    }

    fn remove(&self, id: Uuid) -> Result<bool, VaultError> {
        let all = self.get_all()?;
        let mut bak_path = self.path.clone();
        if !bak_path.set_extension(".bak") {
            return Err(VaultError::FilesystemError(
                "Failed to initialized backup".to_string(),
            ));
        }

        if !fs::rename(&self.path, &bak_path).is_ok() {
            return Err(VaultError::FilesystemError(
                "Failed to make a backup".to_string(),
            ));
        }

        let mut wrt = csv::WriterBuilder::new()
            .has_headers(true)
            .from_path(&self.path)?;

        let mut err: Option<ConversionError> = None;
        let mut found = false;
        for item in all {
            if item.id != id {
                let data: Result<Vec<u8>, ConversionError> = item.details.try_into();
                match data {
                    Ok(data) => {
                        AddressbookStorage::write(
                            &mut wrt,
                            CsvRecord {
                                id: item.id.to_string(),
                                format: FORMAT.to_string(),
                                data: base64::encode(&data),
                            },
                        )?;
                    }
                    Err(e) => {
                        err = Some(e);
                    }
                };
            } else {
                found = true;
            }
        }
        wrt.flush()?;

        if err.is_some() {
            // Restore backup if error happened
            if fs::remove_file(&self.path).is_err() {
                warn!("Failed to remove tmp file")
            }
            if fs::rename(&bak_path, &self.path).is_err() {
                error!("Failed to restore original file")
            }
            Err(VaultError::ConversionError(err.unwrap()))
        } else {
            Ok(found)
        }
    }

    fn update(&self, entry: AddressBookmark) -> Result<bool, VaultError> {
        //TODO atomic update, in one rewrite
        let id = entry.get_id();
        if self.remove(id)? {
            self.add(entry)?;
            Ok(true)
        } else {
            Err(VaultError::IncorrectIdError)
        }
    }

    fn update_multiple(&self, entry: AddressBookmark, archive: &Archive) -> Result<bool, VaultError> {
        self.update(entry)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        blockchain::chains::Blockchain,
        storage::{
            addressbook::{AddressBookmark, AddressbookStorage},
            vault::VaultAccess,
        },
        structs::book::{AddressRef, BookmarkDetails},
        EthereumAddress,
    };
    use chrono::Utc;
    use std::{fs, path::Path, str::FromStr};
    use tempdir::TempDir;
    use uuid::Uuid;

    fn extract_address_str(details: &BookmarkDetails) -> Option<String> {
        match details.address {
            AddressRef::EthereumAddress(s) => Some(s.to_string()),
            _ => panic!("not implemented for ext"),
        }
    }

    fn dump_file<P>(path: P)
    where
        P: AsRef<Path>,
    {
        let f = fs::read(path.as_ref()).expect("read csv");
        println!("{}", String::from_utf8(f).expect("Non UTF8 content"));
    }

    // ----

    #[test]
    fn read_empty() {
        let book = AddressbookStorage::from_path("./tests/addressbook/empty.csv");
        let act = book.get_all().expect("get_all() failed");
        assert_eq!(0, act.len());
        let act = book.list().expect("list() failed");
        assert_eq!(0, act.len());
    }

    #[test]
    fn read_one() {
        let book = AddressbookStorage::from_path("./tests/addressbook/one_item.csv");
        let all = book.get_all().expect("get_all() failed");
        assert_eq!(1, all.len());
        let item = all.first().unwrap();
        assert_eq!("9c404f6f-49a1-4911-9ee2-feaa6abb03f1", item.id.to_string());
        assert_eq!(Blockchain::Ethereum, item.details.blockchain);
        assert_eq!("Test!", item.details.label.clone().expect("Label not set"));
        assert!(item.details.description.is_none());
        assert_eq!(
            Some("0x085fb4f24031eaedbc2b611aa528f22343eb52db".to_string()),
            extract_address_str(&item.details)
        );
    }

    #[test]
    fn read_without_header() {
        let book = AddressbookStorage::from_path("./tests/addressbook/one_item_no_header.csv");
        let all = book.get_all().expect("get_all() failed");
        assert_eq!(1, all.len());
        let item = all.first().unwrap();
        assert_eq!("9c404f6f-49a1-4911-9ee2-feaa6abb03f1", item.id.to_string());
        assert_eq!(Blockchain::Ethereum, item.details.blockchain);
        assert_eq!("Test!", item.details.label.clone().expect("Label not set"));
        assert!(item.details.description.is_none());
        assert_eq!(
            Some("0x085fb4f24031eaedbc2b611aa528f22343eb52db".to_string()),
            extract_address_str(&item.details)
        );
    }

    #[test]
    fn get_one_by_id() {
        let book = AddressbookStorage::from_path("./tests/addressbook/one_item.csv");
        let item = book
            .get(Uuid::from_str("9c404f6f-49a1-4911-9ee2-feaa6abb03f1").unwrap())
            .expect("get_all() failed");
        assert_eq!("9c404f6f-49a1-4911-9ee2-feaa6abb03f1", item.id.to_string());
        assert_eq!(Blockchain::Ethereum, item.details.blockchain);
        assert_eq!("Test!", item.details.label.clone().expect("Label not set"));
        assert!(item.details.description.is_none());
        assert_eq!(
            Some("0x085fb4f24031eaedbc2b611aa528f22343eb52db".to_string()),
            extract_address_str(&item.details)
        );
    }

    #[test]
    fn write_one() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let book = AddressbookStorage::from_path(tmp_dir.into_path().join("addressbook.csv"));
        let item = AddressBookmark {
            id: Uuid::from_str("9c404f6f-49a1-4911-9ee2-feaa6abb03f1").unwrap(),
            details: BookmarkDetails {
                blockchain: Blockchain::Ethereum,
                label: Some("Hello World!".to_string()),
                description: None,
                address: AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x085fb4f24031eaedbc2b611aa528f22343eb52db")
                        .unwrap(),
                ),
                created_at: Utc::now(),
            },
        };
        let act = book.add(item);
        assert!(act.is_ok());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(1, all.len());
        let item = all.first().unwrap();
        assert_eq!("9c404f6f-49a1-4911-9ee2-feaa6abb03f1", item.id.to_string());
        assert_eq!(Blockchain::Ethereum, item.details.blockchain);
        assert_eq!(
            "Hello World!",
            item.details.label.clone().expect("Label not set")
        );
        assert!(item.details.description.is_none());
        assert_eq!(
            Some("0x085fb4f24031eaedbc2b611aa528f22343eb52db".to_string()),
            extract_address_str(&item.details)
        );
    }

    #[test]
    fn add_few_and_remove_all() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let book = AddressbookStorage::from_path(tmp_dir.into_path().join("addressbook.csv"));
        let item1 = AddressBookmark {
            id: Uuid::from_str("6f42441b-1541-4e29-9f5e-5fef6c79fb9a").unwrap(),
            details: BookmarkDetails {
                blockchain: Blockchain::Ethereum,
                label: Some("Hello World 1".to_string()),
                description: None,
                address: AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x5bee6233f7e2307746266deb0678f22686932c26")
                        .unwrap(),
                ),
                created_at: Utc::now(),
            },
        };
        let item2 = AddressBookmark {
            id: Uuid::from_str("d27171c5-f458-4973-bd00-0415cf1c47aa").unwrap(),
            details: BookmarkDetails {
                blockchain: Blockchain::Ethereum,
                label: Some("Hello World 2".to_string()),
                description: None,
                address: AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x732c628300f2da4d54f988b22eeca520356743dc")
                        .unwrap(),
                ),
                created_at: Utc::now(),
            },
        };
        let item3 = AddressBookmark {
            id: Uuid::from_str("b6b22cc7-1419-4056-b49e-c6bbcde9b4cd").unwrap(),
            details: BookmarkDetails {
                blockchain: Blockchain::Ethereum,
                label: Some("Hello World 3".to_string()),
                description: None,
                address: AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0xfac41abcf13f5dcd83d8c20d5ed5e07e1968a348")
                        .unwrap(),
                ),
                created_at: Utc::now(),
            },
        };

        let added = book.add(item1);
        assert!(added.is_ok());
        let added = book.add(item2);
        assert!(added.is_ok());
        let added = book.add(item3);
        assert!(added.is_ok());

        dump_file(book.path.clone());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(3, all.len());

        let item = all.get(0).unwrap();
        assert_eq!("6f42441b-1541-4e29-9f5e-5fef6c79fb9a", item.id.to_string());
        assert_eq!(
            "Hello World 1",
            item.details.label.clone().expect("Label not set")
        );
        let item = all.get(1).unwrap();
        assert_eq!("d27171c5-f458-4973-bd00-0415cf1c47aa", item.id.to_string());
        assert_eq!(
            "Hello World 2",
            item.details.label.clone().expect("Label not set")
        );
        let item = all.get(2).unwrap();
        assert_eq!("b6b22cc7-1419-4056-b49e-c6bbcde9b4cd", item.id.to_string());
        assert_eq!(
            "Hello World 3",
            item.details.label.clone().expect("Label not set")
        );

        let removed = book.remove(Uuid::from_str("d27171c5-f458-4973-bd00-0415cf1c47aa").unwrap());
        assert!(removed.is_ok());
        assert_eq!(true, removed.unwrap());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(2, all.len());
        let item = all.get(0).unwrap();
        assert_eq!(
            "Hello World 1",
            item.details.label.clone().expect("Label not set")
        );
        let item = all.get(1).unwrap();
        assert_eq!(
            "Hello World 3",
            item.details.label.clone().expect("Label not set")
        );

        let removed = book.remove(Uuid::from_str("d27171c5-f458-4973-bd00-0415cf1c47aa").unwrap());
        assert!(removed.is_ok());
        assert_eq!(false, removed.unwrap());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(2, all.len());
        let item = all.get(0).unwrap();
        assert_eq!(
            "Hello World 1",
            item.details.label.clone().expect("Label not set")
        );
        let item = all.get(1).unwrap();
        assert_eq!(
            "Hello World 3",
            item.details.label.clone().expect("Label not set")
        );

        let removed = book.remove(Uuid::from_str("b6b22cc7-1419-4056-b49e-c6bbcde9b4cd").unwrap());
        assert!(removed.is_ok());
        assert_eq!(true, removed.unwrap());

        //        dump_file(book.path.clone());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(1, all.len());
        let item = all.get(0).unwrap();
        assert_eq!(
            "Hello World 1",
            item.details.label.clone().expect("Label not set")
        );

        let removed = book.remove(Uuid::from_str("6f42441b-1541-4e29-9f5e-5fef6c79fb9a").unwrap());
        assert!(removed.is_ok());
        assert_eq!(true, removed.unwrap());

        //        dump_file(book.path.clone());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(0, all.len());
    }
}
