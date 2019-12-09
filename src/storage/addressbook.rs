/*
Copyright 2019 ETCDEV GmbH

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

use glob::glob;
use serde_json;
use std::fs::{remove_file, OpenOptions};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use uuid::Uuid;
use crate::{
    convert::{
        proto::book::{BookmarkDetails},
        error::ConversionError,
        proto::types::HasUuid
    },
    storage::{
        vault::VaultAccess,
        error::VaultError
    },
    core::Address,
};
use std::convert::{TryFrom, TryInto};
use std::fs;
use csv::{Writer, StringRecord};

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
    data: String
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddressBookmark {
    pub id: Uuid,
    pub details: BookmarkDetails
}

impl HasUuid for AddressBookmark {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl TryFrom<CsvRecord> for AddressBookmark {
    type Error = ConversionError;

    fn try_from(value: CsvRecord) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&value.id)
            .map_err(|_| ConversionError::InvalidData("id".to_string()))?;
        if FORMAT != value.format {
            return Err(ConversionError::InvalidData("format".to_string()))
        }
        let data = base64::decode(&value.data)
            .map_err(|_| ConversionError::InvalidData("data".to_string()))?;
        let details = BookmarkDetails::try_from(data)?;
        let result = AddressBookmark { id, details };
        Ok(result)
    }
}

impl AddressbookStorage {

    pub fn from_path<P>(path: P) -> AddressbookStorage where P: AsRef<Path> {
        AddressbookStorage {
            path: PathBuf::from(path.as_ref())
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
                continue
            }
            let record: CsvRecord = AddressbookStorage::read(line)?;
            let bookmark = AddressBookmark::try_from(record)?;
            result.push(bookmark);
        };
        Ok(result)
    }

    fn read(record: StringRecord) -> Result<CsvRecord, VaultError> {
        if record.len() != 3 {
            return Err(VaultError::UnsupportedDataError("Excessive column".to_string()))
        }
        let result = CsvRecord {
            id: record.get(0).unwrap().to_string(),
            format: record.get(1).unwrap().to_string(),
            data: record.get(2).unwrap().to_string()
        };
        Ok(result)
    }

    fn write(wrt: &mut Writer<File>, record: CsvRecord) -> Result<(), VaultError> {
        let mut line = Vec::new();
        line.push(record.id);
        line.push(FORMAT.to_string());
        line.push(record.data);
        wrt.write_record(&line)
            .map_err(|e| VaultError::FilesystemError("CSV record not written".to_string()))
    }
}

impl VaultAccess<AddressBookmark> for AddressbookStorage {

    fn list_entries(&self) -> Result<Vec<AddressBookmark>, VaultError> {
        let all = self.list()?.iter()
            .map(|id| self.get(id))
            .filter(|it| it.is_ok())
            .map(|it| it.unwrap())
            .collect();
        Ok(all)
    }

    fn list(&self) -> Result<Vec<Uuid>, VaultError> {
        let ids = self.get_all()?.iter()
            .map(|b| b.id)
            .collect();
        Ok(ids)
    }

    fn get(&self, id: &Uuid) -> Result<AddressBookmark, VaultError> {
        let all = self.get_all()?;
        let found = all.iter().find(|b| b.id == *id);
        if found.is_none() {
            Err(VaultError::IncorrectIdError)
        } else {
            Ok(found.unwrap().clone())
        }
    }

    fn add(&self, item: AddressBookmark) -> Result<(), VaultError> {
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
        AddressbookStorage::write(&mut wrt, CsvRecord {
            id: item.id.to_string(),
            format: FORMAT.to_string(),
            data: base64::encode(&data)
        })?;
        wrt.flush();
        Ok(())
    }

    fn remove(&self, id: &Uuid) -> Result<bool, VaultError> {
        let all = self.get_all()?;
        let mut bak_path = self.path.clone();
        if !bak_path.set_extension(".bak") {
            return Err(VaultError::FilesystemError("Failed to initialized backup".to_string()))
        }

        if !fs::rename(&self.path, &bak_path).is_ok() {
            return Err(VaultError::FilesystemError("Failed to make a backup".to_string()))
        }

        let mut wrt = csv::WriterBuilder::new()
            .has_headers(true)
            .from_path(&self.path)?;

        let mut err: Option<VaultError> = None;
        let mut found = false;
        for item in all {
            if item.id != *id {
                let data: Result<Vec<u8>, VaultError> = item.details.try_into();
                match data {
                    Ok(data) => {
                        AddressbookStorage::write(&mut wrt, CsvRecord {
                            id: item.id.to_string(),
                            format: FORMAT.to_string(),
                            data: base64::encode(&data)
                        });
                    },
                    Err(e) => {
                        err = Some(e);
                    }
                };
            } else {
                found = true;
            }
        }
        wrt.flush();

        if err.is_some() {
            // Restore backup if error happened
            fs::remove_file(&self.path);
            fs::rename(&bak_path, &self.path);
            Err(err.unwrap())
        } else {
            Ok(found)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        storage::{
            vault::VaultAccess,
            addressbook::AddressBookmark
        },
        convert::proto::book::{
            BookmarkDetails,
            AddressRef
        },
        Address,
        core::chains::Blockchain,
    };
    use uuid::Uuid;
    use std::str::FromStr;
    use tempdir::TempDir;
    use std::fs::File;
    use std::fs;
    use std::path::Path;
    use crate::storage::addressbook::AddressbookStorage;

    fn extract_address_str(details: &BookmarkDetails) -> Option<String> {
        match details.address {
            AddressRef::EthereumAddress(s) => Some(s.to_string())
        }
    }

    fn dump_file<P>(path: P) where P: AsRef<Path> {
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
        assert_eq!(vec![Blockchain::Ethereum], item.details.blockchains);
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
        assert_eq!(vec![Blockchain::Ethereum], item.details.blockchains);
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
        let item = book.get(&Uuid::from_str("9c404f6f-49a1-4911-9ee2-feaa6abb03f1").unwrap()).expect("get_all() failed");
        assert_eq!("9c404f6f-49a1-4911-9ee2-feaa6abb03f1", item.id.to_string());
        assert_eq!(vec![Blockchain::Ethereum], item.details.blockchains);
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
                blockchains: vec![Blockchain::Ethereum],
                label: Some("Hello World!".to_string()),
                description: None,
                address: AddressRef::EthereumAddress(Address::from_str("0x085fb4f24031eaedbc2b611aa528f22343eb52db").unwrap())
            }
        };
        let act = book.add(item);
        assert!(act.is_ok());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(1, all.len());
        let item = all.first().unwrap();
        assert_eq!("9c404f6f-49a1-4911-9ee2-feaa6abb03f1", item.id.to_string());
        assert_eq!(vec![Blockchain::Ethereum], item.details.blockchains);
        assert_eq!("Hello World!", item.details.label.clone().expect("Label not set"));
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
                blockchains: vec![Blockchain::Ethereum],
                label: Some("Hello World 1".to_string()),
                description: None,
                address: AddressRef::EthereumAddress(Address::from_str("0x5bee6233f7e2307746266deb0678f22686932c26").unwrap())
            }
        };
        let item2 = AddressBookmark {
            id: Uuid::from_str("d27171c5-f458-4973-bd00-0415cf1c47aa").unwrap(),
            details: BookmarkDetails {
                blockchains: vec![Blockchain::Ethereum],
                label: Some("Hello World 2".to_string()),
                description: None,
                address: AddressRef::EthereumAddress(Address::from_str("0x732c628300f2da4d54f988b22eeca520356743dc").unwrap())
            }
        };
        let item3 = AddressBookmark {
            id: Uuid::from_str("b6b22cc7-1419-4056-b49e-c6bbcde9b4cd").unwrap(),
            details: BookmarkDetails {
                blockchains: vec![Blockchain::Ethereum],
                label: Some("Hello World 3".to_string()),
                description: None,
                address: AddressRef::EthereumAddress(Address::from_str("0xfac41abcf13f5dcd83d8c20d5ed5e07e1968a348").unwrap())
            }
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
        assert_eq!("Hello World 1", item.details.label.clone().expect("Label not set"));
        let item = all.get(1).unwrap();
        assert_eq!("d27171c5-f458-4973-bd00-0415cf1c47aa", item.id.to_string());
        assert_eq!("Hello World 2", item.details.label.clone().expect("Label not set"));
        let item = all.get(2).unwrap();
        assert_eq!("b6b22cc7-1419-4056-b49e-c6bbcde9b4cd", item.id.to_string());
        assert_eq!("Hello World 3", item.details.label.clone().expect("Label not set"));

        let removed = book.remove(&Uuid::from_str("d27171c5-f458-4973-bd00-0415cf1c47aa").unwrap());
        assert!(removed.is_ok());
        assert_eq!(true, removed.unwrap());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(2, all.len());
        let item = all.get(0).unwrap();
        assert_eq!("Hello World 1", item.details.label.clone().expect("Label not set"));
        let item = all.get(1).unwrap();
        assert_eq!("Hello World 3", item.details.label.clone().expect("Label not set"));


        let removed = book.remove(&Uuid::from_str("d27171c5-f458-4973-bd00-0415cf1c47aa").unwrap());
        assert!(removed.is_ok());
        assert_eq!(false, removed.unwrap());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(2, all.len());
        let item = all.get(0).unwrap();
        assert_eq!("Hello World 1", item.details.label.clone().expect("Label not set"));
        let item = all.get(1).unwrap();
        assert_eq!("Hello World 3", item.details.label.clone().expect("Label not set"));

        let removed = book.remove(&Uuid::from_str("b6b22cc7-1419-4056-b49e-c6bbcde9b4cd").unwrap());
        assert!(removed.is_ok());
        assert_eq!(true, removed.unwrap());

//        dump_file(book.path.clone());

        let all = book.get_all().expect("get_all() failed");
        assert_eq!(1, all.len());
        let item = all.get(0).unwrap();
        assert_eq!("Hello World 1", item.details.label.clone().expect("Label not set"));

        let removed = book.remove(&Uuid::from_str("6f42441b-1541-4e29-9f5e-5fef6c79fb9a").unwrap());
        assert!(removed.is_ok());
        assert_eq!(true, removed.unwrap());

//        dump_file(book.path.clone());


        let all = book.get_all().expect("get_all() failed");
        assert_eq!(0, all.len());

    }
}
