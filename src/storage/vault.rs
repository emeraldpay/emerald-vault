use uuid::Uuid;
use std::path::{Path, PathBuf};
use std::fs;
use regex::Regex;
use std::str::FromStr;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use crate::{storage::{
    archive::Archive,
    error::VaultError
}, chains::Blockchain, convert::{
    json::keyfile::EthereumJsonV3File,
}, structs::{
    pk::{
        PrivateKeyHolder
    },
    wallet::{
        WalletAccount,
        PKType,
        Wallet
    },
    types::{
        HasUuid
    },
    seed::Seed
}, Address};
use crate::storage::addressbook::AddressbookStorage;
use crate::hdwallet::bip32::{HDPath, generate_key};
use crate::structs::seed::{SeedSource, SeedRef};


pub struct VaultStorage {
    dir: PathBuf,
    pub archive: Archive,

    keys: Arc<dyn VaultAccess<PrivateKeyHolder>>,
    wallets: Arc<dyn VaultAccess<Wallet>>,
    seeds: Arc<dyn VaultAccess<Seed>>,
}

struct StandardVaultFiles {
    dir: PathBuf,
    suffix: String
}

impl VaultStorage {
    pub fn keys(&self) -> Arc<dyn VaultAccess<PrivateKeyHolder>> {
        self.keys.clone()
    }
    pub fn wallets(&self) -> Arc<dyn VaultAccess<Wallet>> {
        self.wallets.clone()
    }
    pub fn seeds(&self) -> Arc<dyn VaultAccess<Seed>> {
        self.seeds.clone()
    }
    pub fn create_new(&self) -> CreateWallet {
        CreateWallet {
            keys: self.keys(),
            wallets: self.wallets(),
            seeds: self.seeds()
        }
    }
    pub fn addressbook(&self) -> AddressbookStorage {
        AddressbookStorage::from_path(self.dir.clone().join("addressbook.csv"))
    }
    pub fn add_account(&self, wallet_id: Uuid) -> AddAccount {
        AddAccount {
            keys: self.keys().clone(),
            seeds: self.seeds().clone(),
            wallets: self.wallets().clone(),
            wallet_id
        }
    }
}

fn as_filename(uuid: &Uuid, suffix: &str) -> String {
    format!("{}.{}", uuid, suffix)
}

fn try_vault_file(file: &Path, suffix: &str) -> Result<Uuid, ()> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(?P<id>[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\.(?P<suffix>[a-z]+)").unwrap();
    }

    match file.file_name() {
        Some(name) => {
            let file_name = name.to_str().unwrap();
            match RE.captures(file_name) {
                Some(caps) => {
                    let act_suffix = caps.name("suffix").unwrap().as_str();
                    if act_suffix.eq(suffix) {
                        let id: &str = caps.name("id").unwrap().as_str();
                        let uuid = Uuid::from_str(id).unwrap();
                        if as_filename(&uuid, suffix).eq(file_name) {
                            Ok(uuid)
                        } else {
                            Err(())
                        }
                    } else {
                        Err(())
                    }
                }
                None => Err(())
            }
        },
        None => Err(())
    }
}

pub struct CreateWallet {
    keys: Arc<dyn VaultAccess<PrivateKeyHolder>>,
    wallets: Arc<dyn VaultAccess<Wallet>>,
    seeds: Arc<dyn VaultAccess<Seed>>,
}

impl CreateWallet {
    pub fn ethereum(&self, json: &EthereumJsonV3File, blockchain: Blockchain) -> Result<Uuid, VaultError> {
        let mut pk = PrivateKeyHolder::try_from(json).map_err(|e| VaultError::ConversionError)?;
        pk.generate_id();
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: json.name.clone(),
            accounts: vec![
                WalletAccount {
                    blockchain,
                    address: json.address,
                    key: PKType::PrivateKeyRef(pk.get_id())
                }
            ]
        };
        let result = wallet.get_id();
        self.keys.add(pk)?;
        self.wallets.add(wallet)?;
        Ok(result)
    }

    pub fn raw_pk(&self, pk: Vec<u8>, password: &str, blockchain: Blockchain) -> Result<Uuid, VaultError> {
        let pk = PrivateKeyHolder::create_ethereum_raw(pk, password)
            .map_err(|e| VaultError::InvalidDataError("Invalid PrivateKey".to_string()))?;
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: None,
            accounts: vec![
                WalletAccount {
                    blockchain,
                    address: pk.get_ethereum_address(),
                    key: PKType::PrivateKeyRef(pk.get_id())
                }
            ]
        };
        let result = wallet.get_id();
        self.keys.add(pk)?;
        self.wallets.add(wallet)?;
        Ok(result)
    }
}

pub struct AddAccount {
    keys: Arc<dyn VaultAccess<PrivateKeyHolder>>,
    seeds: Arc<dyn VaultAccess<Seed>>,
    wallets: Arc<dyn VaultAccess<Wallet>>,
    wallet_id: Uuid
}

impl AddAccount {
    pub fn ethereum(&self, json: &EthereumJsonV3File, blockchain: Blockchain) -> Result<u32, VaultError> {
        let mut wallet = self.wallets.get(&self.wallet_id)?;
        let mut pk = PrivateKeyHolder::try_from(json).map_err(|e| VaultError::ConversionError)?;
        let pk_id = pk.generate_id();
        self.keys.add(pk)?;
        wallet.accounts.push(
            WalletAccount {
                blockchain,
                address: json.address,
                key: PKType::PrivateKeyRef(pk_id)
            }
        );
        self.wallets.update(wallet.clone());
        Ok(wallet.accounts.len() as u32 - 1)
    }

    pub fn raw_pk(&mut self, pk: Vec<u8>, password: &str, blockchain: Blockchain) -> Result<u32, VaultError> {
        let mut wallet = self.wallets.get(&self.wallet_id)?;
        let pk = PrivateKeyHolder::create_ethereum_raw(pk, password)
            .map_err(|e| VaultError::InvalidDataError("Invalid PrivateKey".to_string()))?;
        let pk_id = pk.get_id();
        let address = pk.get_ethereum_address().clone();
        self.keys.add(pk)?;
        wallet.accounts.push(
            WalletAccount {
                blockchain,
                address,
                key: PKType::PrivateKeyRef(pk_id)
            }
        );
        self.wallets.update(wallet.clone());
        Ok(wallet.accounts.len() as u32 - 1)
    }

    pub fn seed_hd(&self, seed_id: Uuid, hd_path: HDPath, blockchain: Blockchain,
                   password: Option<String>, expected_address: Option<Address>) -> Result<u32, VaultError> {
        let seed = self.seeds.get(&seed_id)?;
        let seed = match seed.source {
            SeedSource::Bytes(seed) => {
                if password.is_none() {
                    return Err(VaultError::PasswordRequired);
                }
                seed.decrypt(password.unwrap().as_str())?
            },
            _ => return Err(VaultError::UnsupportedDataError("No implemented yet".to_string()))
        };
        let mut wallet = self.wallets.get(&self.wallet_id)?;
        let ephemeral_pk = generate_key(&hd_path, seed.as_slice())?;
        let address = ephemeral_pk.to_address();
        if expected_address.is_some() && address != expected_address.unwrap() {
            return Err(VaultError::InvalidDataError("Different address".to_string()));
        }

        wallet.accounts.push(
            WalletAccount {
                blockchain,
                address: Some(address),
                key: PKType::SeedHd(SeedRef { seed_id, hd_path: hd_path.to_string() })
            }
        );
        self.wallets.update(wallet.clone());
        Ok(wallet.accounts.len() as u32 - 1)
    }
}

impl VaultStorage {
    pub fn create<P: AsRef<Path>>(path: P) -> Result<VaultStorage, VaultError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        if !path.is_dir() {
            return Err(VaultError::FilesystemError("Target path is not a dir".to_string()))
        }
        Ok(VaultStorage {
            dir: path.clone(),
            archive: Archive::create(path.clone()),
            keys: Arc::new(StandardVaultFiles { dir: path.clone(), suffix: "key".to_string() }),
            wallets: Arc::new(StandardVaultFiles { dir: path.clone(), suffix: "wallet".to_string() }),
            seeds: Arc::new(StandardVaultFiles { dir: path.clone(), suffix: "seed".to_string() }),
        })
    }
}

pub trait VaultAccess<P> where P: HasUuid {
    fn list(&self) -> Result<Vec<Uuid>, VaultError>;
    fn get(&self, id: &Uuid) -> Result<P, VaultError>;
    fn add(&self, entry: P) -> Result<Uuid, VaultError>;
    fn remove(&self, id: &Uuid) -> Result<bool, VaultError>;

    fn list_entries(&self) -> Result<Vec<P>, VaultError> {
        let all = self.list()?.iter()
            .map(|id| self.get(id))
            .filter(|it| it.is_ok())
            .map(|it| it.unwrap())
            .collect();
        Ok(all)
    }

    fn update(&self, entry: P) -> Result<bool, VaultError> {
        //TODO safe update, with .bak/.tmp files
        let id = entry.get_id();
        if self.remove(&id)? {
            self.add(entry);
            Ok(true)
        } else {
            Err(VaultError::IncorrectIdError)
        }
    }
}

impl <P> VaultAccess<P> for StandardVaultFiles
    where P: TryFrom<Vec<u8>> + HasUuid,
          Vec<u8>: std::convert::TryFrom<P> {

    fn list(&self) -> Result<Vec<Uuid>, VaultError> {
        let mut result = Vec::new();
        if self.dir.is_dir() {
            for entry in fs::read_dir(&self.dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    match try_vault_file(&path, self.suffix.as_str()) {
                        Ok(id) => {result.push(id);}
                        Err(_) => {}
                    }
                }
            }
        }
        Ok(result)
    }

    fn get(&self, id: &Uuid) -> Result<P, VaultError> {
        let f = self.dir.join(Path::new(as_filename(id, self.suffix.as_str()).as_str()));

        let data = fs::read(f)?;
        let pk = P::try_from(data).map_err(|e| VaultError::ConversionError)?;
        if !pk.get_id().eq(id) {
            Err(VaultError::IncorrectIdError)
        } else {
            Ok(pk)
        }
    }

    fn add(&self, entry: P) -> Result<Uuid, VaultError> {
        let id = entry.get_id();
        let f = self.dir.join(Path::new(as_filename(&id, self.suffix.as_str()).as_str()));
        if f.exists() {
            return Err(VaultError::FilesystemError("Already exists".to_string()));
        }

        let data: Vec<u8> = entry.try_into()
            .map_err(|x| VaultError::ConversionError)?;
//        let data: Vec<u8> = Vec::try_from(pk)?;
        fs::write(f, data.as_slice())?;
        Ok(id)
    }

    fn remove(&self, id: &Uuid) -> Result<bool, VaultError> {
        let f = self.dir.join(Path::new(as_filename(&id, self.suffix.as_str()).as_str()));
        if !f.exists() {
            return Ok(false)
        }
        if !f.is_file() {
            return Err(VaultError::FilesystemError("Not a file".to_string()))
        }
        //TODO move to trash
        fs::remove_file(f)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;
    use crate::{
        structs::{
            pk::{
                PrivateKeyHolder,
                EthereumPk3
            },
            crypto::Encrypted
        },
        tests::*,
        convert::json::keyfile::EthereumJsonV3File
    };


    #[test]
    fn try_vault_file_from_standard() {
        let act = try_vault_file(Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.key"), "key");
        assert!(act.is_ok());
        assert_eq!(Uuid::from_str("3221aabc-b3ff-4235-829f-9599aba04cb5").unwrap(), act.unwrap());
    }

    #[test]
    fn try_vault_file_from_invalid_suffix() {
        let act = try_vault_file(Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.seed"), "key");
        assert!(act.is_err());
    }

    #[test]
    fn try_vault_file_from_invalid_name() {
        let act = try_vault_file(Path::new("9599aba04cb5.key"), "key");
        assert!(act.is_err());
        let act = try_vault_file(Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.key.bak"), "key");
        assert!(act.is_err());
        let act = try_vault_file(Path::new("~3221aabc-b3ff-4235-829f-9599aba04cb5.key"), "key");
        assert!(act.is_err());
        let act = try_vault_file(Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.~key"), "key");
        assert!(act.is_err());
        let act = try_vault_file(Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.key~"), "key");
        assert!(act.is_err());
    }

    #[test]
    fn add_single_pk() {
        let json = r#"
            {
                "version": 3,
                "id": "305f4853-80af-4fa6-8619-6f285e83cf28",
                "address": "6412c428fc02902d137b60dc0bd0f6cd1255ea99",
                "name": "Hello",
                "description": "World!!!!",
                "visible": true,
                "crypto": {
                    "cipher": "aes-128-ctr",
                    "cipherparams": {"iv": "e4610fb26bd43fa17d1f5df7a415f084"},
                    "ciphertext": "dc50ab7bf07c2a793206683397fb15e5da0295cf89396169273c3f49093e8863",
                    "kdf": "scrypt",
                    "kdfparams": {
                        "dklen": 32,
                        "salt": "86c6a8857563b57be9e16ad7a3f3714f80b714bcf9da32a2788d695a194f3275",
                        "n": 1024,
                        "r": 8,
                        "p": 1
                    },
                    "mac": "8dfedc1a92e2f2ca1c0c60cd40fabb8fb6ce7c05faf056281eb03e0a9996ecb0"
                }
            }
        "#;
        let json = EthereumJsonV3File::try_from(json.to_string()).expect("JSON not parsed");
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");

        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let vault_pk = vault.keys();
        let pk = PrivateKeyHolder::create_ethereum_v3(EthereumPk3::try_from(&json).unwrap());
        let pk_id = pk.id;
        let saved = vault_pk.add(pk);
        assert!(saved.is_ok());

        let list = vault_pk.list().unwrap();
        assert_eq!(1, list.len());
        assert_eq!(pk_id, list[0]);

        let stored: PrivateKeyHolder = vault_pk.get(&pk_id).unwrap();
    }

    #[test]
    fn remove_after_adding() {
        let json = r#"
            {
                "version": 3,
                "id": "305f4853-80af-4fa6-8619-6f285e83cf28",
                "address": "6412c428fc02902d137b60dc0bd0f6cd1255ea99",
                "name": "Hello",
                "description": "World!!!!",
                "visible": true,
                "crypto": {
                    "cipher": "aes-128-ctr",
                    "cipherparams": {"iv": "e4610fb26bd43fa17d1f5df7a415f084"},
                    "ciphertext": "dc50ab7bf07c2a793206683397fb15e5da0295cf89396169273c3f49093e8863",
                    "kdf": "scrypt",
                    "kdfparams": {
                        "dklen": 32,
                        "salt": "86c6a8857563b57be9e16ad7a3f3714f80b714bcf9da32a2788d695a194f3275",
                        "n": 1024,
                        "r": 8,
                        "p": 1
                    },
                    "mac": "8dfedc1a92e2f2ca1c0c60cd40fabb8fb6ce7c05faf056281eb03e0a9996ecb0"
                }
            }
        "#;
        let json = EthereumJsonV3File::try_from(json.to_string()).expect("JSON not parsed");
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let vault_pk = vault.keys();
        let pk = PrivateKeyHolder::create_ethereum_v3(EthereumPk3::try_from(&json).unwrap());
        let exp_id = pk.id;
        let saved = vault_pk.add(pk);
        assert!(saved.is_ok());

        let list = vault_pk.list().unwrap();
        assert_eq!(1, list.len());

        let deleted = vault_pk.remove(&exp_id);
        assert!(deleted.is_ok());
        assert!(deleted.unwrap());

        let list = vault_pk.list().unwrap();
        assert_eq!(0, list.len());
    }

    #[test]
    fn creates_seed() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let all = vault.seeds.list().unwrap();
        assert_eq!(0, all.len());

        let seed = Seed::generate(None, "testtest").unwrap();
        let id = seed.get_id();
        let added = vault.seeds.add(seed.clone());
        assert!(added.is_ok());

        let all = vault.seeds.list();
        assert_eq!(vec![id], all.unwrap());
        let seed_act = vault.seeds.get(&id).expect("Seed not available");
        assert_eq!(seed, seed_act);
    }

    #[test]
    fn deletes_seed() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed = Seed::generate(None, "testtest").unwrap();
        let id = seed.get_id();
        let added = vault.seeds.add(seed.clone());
        assert!(added.is_ok());

        let all = vault.seeds.list();
        assert_eq!(vec![id], all.unwrap());
        let seed_act = vault.seeds.get(&id).expect("Seed not available");
        assert_eq!(seed, seed_act);

        let deleted = vault.seeds.remove(&id);
        assert!(deleted.is_ok());
        assert!(deleted.unwrap());

        let all = vault.seeds.list().unwrap();
        assert_eq!(0, all.len());
    }
}
