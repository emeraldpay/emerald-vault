use uuid::Uuid;
use crate::{
    structs::{
        seed::{
            SeedRef,
            SeedSource
        },
        types::HasUuid,
        pk::PrivateKeyType
    },
    Address,
    core::{
        chains::{
            Blockchain,
            EthereumChainId
        }
    },
    Transaction,
    PrivateKey,
    storage::{
        error::VaultError,
        vault::VaultStorage,
    },
    crypto::error::CryptoError,
    mnemonic::{HDPath, generate_key},
    convert::json::keyfile::EthereumJsonV3File,
    proto::crypto::Encrypted,
};
use regex::Regex;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Wallet {
    pub id: Uuid,
    pub label: Option<String>,
    pub accounts: Vec<WalletAccount>
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WalletAccount {
    pub id: usize,
    pub blockchain: Blockchain,
    pub address: Option<Address>,
    pub key: PKType
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PKType {
    PrivateKeyRef(Uuid),
    SeedHd(SeedRef)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountId {
    pub wallet_id: Uuid,
    pub account_id: usize
}

impl HasUuid for Wallet {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl Wallet {
    pub fn get_account(&self, id: usize) -> Result<WalletAccount, VaultError> {
        let found = self.accounts.iter()
            .find(|a| a.id == id);
        if found.is_none() {
            Err(VaultError::DataNotFound)
        } else {
            Ok(found.unwrap().clone())
        }
    }

    pub fn get_account_id(&self) -> usize {
        //TODO consider removed last account, i.e. remember ids
        let current = self.accounts.iter()
            .map(|a| a.id)
            .max();
        match current {
            Some(id) => id + 1,
            None => 0
        }
    }
}

lazy_static! {
    static ref ACCOUNT_RE: Regex = Regex::new(r"^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})-([0-9]+)$").unwrap();
}

impl AccountId {
    pub fn from(wallet: &Wallet, account: &WalletAccount) -> AccountId {
        AccountId {
            wallet_id: wallet.id.clone(),
            account_id: account.id
        }
    }

    pub fn from_str(value: &str) -> Result<AccountId, VaultError> {
        let cap = ACCOUNT_RE.captures(value);
        match cap {
            Some(cap) => Ok(AccountId {
                wallet_id: Uuid::from_str(cap.get(1).unwrap().as_str()).unwrap(),
                account_id: cap.get(2).unwrap().as_str().parse::<usize>().unwrap()
            }),
            None => Err(VaultError::ConversionError)
        }
    }
}

impl ToString for AccountId {
    fn to_string(&self) -> String {
        return format!("{}-{}", self.wallet_id, self.account_id)
    }
}

impl WalletAccount {

    pub fn get_full_id(&self, wallet: &Wallet) -> AccountId {
        AccountId::from(wallet, self)
    }

    fn sign_tx_by_pk(&self, tx: Transaction, key: PrivateKey) -> Result<Vec<u8>, VaultError> {
        let chain_id = EthereumChainId::from(self.blockchain);
        tx.to_signed_raw(key, chain_id)
            .map_err(|e| VaultError::InvalidPrivateKey)
    }

    fn is_hardware(&self, vault: &VaultStorage) -> Result<bool, VaultError> {
        match &self.key {
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(&seed.seed_id)?;
                match seed_details.source {
                    SeedSource::Ledger(ledger) => {
                        Ok(true)
                    }
                    SeedSource::Bytes(_) => Ok(false)
                }
            },
            PKType::PrivateKeyRef(_) => Ok(false)
        }
    }

    pub fn sign_tx(&self, tx: Transaction, password: Option<String>, vault: &VaultStorage) -> Result<Vec<u8>, VaultError> {
        if self.is_hardware(vault)? {
            unimplemented!()
        }
        if password.is_none() {
            return Err(VaultError::PasswordRequired);
        }
        let key = self.export_pk(password.unwrap(), vault)?;
        self.sign_tx_by_pk(tx, key)
    }

    pub fn export_pk(&self, password: String, vault: &VaultStorage) -> Result<PrivateKey, VaultError> {
        match &self.key {
            PKType::PrivateKeyRef(pk) => {
                let key = vault.keys().get(&pk)?;
                let key = key.decrypt(password.as_str())?;
                PrivateKey::try_from(key.as_slice())
                    .map_err(|e| VaultError::InvalidPrivateKey)
            }
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(&seed.seed_id)?;
                match seed_details.source {
                    SeedSource::Bytes(bytes) => {
                        let seed_key = bytes.decrypt(password.as_str())?;
                        let hd_path = HDPath::try_from(seed.hd_path.as_str())?;
                        generate_key(&hd_path, &seed_key)
                            .map_err(|e| VaultError::InvalidPrivateKey)
                    },
                    SeedSource::Ledger(ledger) => {
                        Err(VaultError::PrivateKeyUnavailable)
                    }
                }
            }
        }
    }

    pub fn export_web3(&self, password: Option<String>, vault: &VaultStorage) -> Result<EthereumJsonV3File, VaultError> {
        match &self.key {
            PKType::PrivateKeyRef(pk) => {
                let key = vault.keys().get(&pk)?;
                EthereumJsonV3File::from_wallet(None, &key)
                    .map_err(|e| VaultError::InvalidPrivateKey)
            }
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(&seed.seed_id)?;
                match seed_details.source {
                    SeedSource::Bytes(bytes) => {
                        if password.is_none() {
                            return Err(VaultError::PasswordRequired)
                        }
                        let password = password.unwrap();
                        let seed_key = bytes.decrypt(password.as_str())?;
                        let hd_path = HDPath::try_from(seed.hd_path.as_str())?;
                        let key = generate_key(&hd_path, &seed_key)
                            .map_err(|e| VaultError::InvalidPrivateKey)?;
                        EthereumJsonV3File::from_pk(None, key, password)
                            .map_err(|e| VaultError::InvalidPrivateKey)
                    },
                    SeedSource::Ledger(ledger) => {
                        Err(VaultError::PrivateKeyUnavailable)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::structs::wallet::{WalletAccount, PKType, AccountId};
    use crate::core::chains::Blockchain;
    use uuid::Uuid;
    use crate::{Transaction, to_32bytes, PrivateKey, Address, ToHex};
    use std::str::FromStr;
    use tempdir::TempDir;
    use crate::storage::vault::VaultStorage;
    use crate::structs::pk::{PrivateKeyHolder, PrivateKeyType, EthereumPk3};
    use crate::structs::crypto::Encrypted;
    use crate::structs::types::HasUuid;
    use crate::structs::seed::{Seed, SeedSource, SeedRef};


    #[test]
    fn sign_with_provided_pk() {
        let account = WalletAccount {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            key: PKType::PrivateKeyRef(Uuid::default()) // not used by the test
        };
        let tx = Transaction {
            nonce: 1,
            gas_price: to_32bytes("04a817c800"),
            gas_limit: 21000,
            to: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            value: to_32bytes("0de0b6b3a7640000"),
            data: vec![]
        };
        let key = PrivateKey::from_str("0x7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d").unwrap();
        let act = account.sign_tx_by_pk(tx, key).unwrap();
        assert_eq!(
            hex::encode(act),
            "f86c018504a817c80082520894008aeeda4d805471df9b2a5b0f38a0c3bcba786b880de0b6b3a76400008026a0d478c7abb05f2cf1c1c118f7f919bc11149b3b2e8b6ac78c5517d6b74aeedcb3a06f0f26ceab9e999b7357087ca1b20f214e0aea58198ace9ee76ff8abe707c9a2"
        )
    }

    #[test]
    fn sign_with_stored_pk() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let raw_pk = hex::decode("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d").unwrap();
        let key = PrivateKeyHolder {
            id: Uuid::new_v4(),
            pk: PrivateKeyType::EthereumPk(EthereumPk3 {
                address: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
                key: Encrypted::encrypt(raw_pk, "testtest").unwrap()
            })
        };
        let key_id = key.get_id();
        vault.keys().add(key);

        let account = WalletAccount {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            key: PKType::PrivateKeyRef(key_id)
        };
        let tx = Transaction {
            nonce: 1,
            gas_price: to_32bytes("04a817c800"),
            gas_limit: 21000,
            to: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            value: to_32bytes("0de0b6b3a7640000"),
            data: vec![]
        };

        let act = account.sign_tx(tx, Some("testtest".to_string()), &vault).unwrap();
        assert_eq!(
            hex::encode(act),
            "f86c018504a817c80082520894008aeeda4d805471df9b2a5b0f38a0c3bcba786b880de0b6b3a76400008026a0d478c7abb05f2cf1c1c118f7f919bc11149b3b2e8b6ac78c5517d6b74aeedcb3a06f0f26ceab9e999b7357087ca1b20f214e0aea58198ace9ee76ff8abe707c9a2"
        )
    }

    #[test]
    fn export_stored_pk() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let raw_pk = hex::decode("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d").unwrap();
        let key = PrivateKeyHolder {
            id: Uuid::new_v4(),
            pk: PrivateKeyType::EthereumPk(EthereumPk3 {
                address: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
                key: Encrypted::encrypt(raw_pk, "testtest").unwrap()
            })
        };
        let key_id = vault.keys().add(key).unwrap();

        let account = WalletAccount {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            key: PKType::PrivateKeyRef(key_id)
        };

        let pk = account.export_pk("testtest".to_string(), &vault).unwrap();
        assert_eq!(
            pk.to_hex(),
            "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
        )
    }

    #[test]
    fn export_pk_from_seed() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed = Seed {
            id: Uuid::new_v4(),
            source: SeedSource::create_bytes(
                hex::decode("0c0727514fe0c87460ddc2bff08075174e1b45283db9d6d34ae23fb877dd12da98d6235f56d9cc4ce3ec245ffe226176338569c59db502ccebfb5c6cd6a264b4").unwrap(),
                "test1234"
            ).unwrap()
        };
        let seed_id = vault.seeds().add(seed).unwrap();

        let account = WalletAccount {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: None, //0xC27fBF02FB577683593b1114180CA6E2c88510A0
            key: PKType::SeedHd(SeedRef {
                seed_id,
                hd_path: "m/44'/60'/2'/0/52".to_string()
            })
        };

        let pk = account.export_pk("test1234".to_string(), &vault).unwrap();
        assert_eq!(
            pk.to_hex(),
            "62a54ec79949cf6eb3bec6d67a3cd5fab835899f80c99785b73e8cd2ae9cfadb"
        )
    }

    #[test]
    fn parse_valid_account_it() {
        let act = AccountId::from_str("94d70ee7-1657-442e-af87-0210e985f29e-1");
        assert!(act.is_ok());
        let act = act.unwrap();
        assert_eq!(1, act.account_id);
        assert_eq!(Uuid::from_str("94d70ee7-1657-442e-af87-0210e985f29e").unwrap(), act.wallet_id);
    }
}
