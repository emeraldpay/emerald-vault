use uuid::Uuid;
use crate::{structs::{
    seed::SeedRef,
    types::HasUuid
}, Address, core::chains::Blockchain, Transaction, PrivateKey};
use crate::storage::error::VaultError;
use crate::crypto::error::CryptoError;
use crate::storage::vault::VaultStorage;
use crate::structs::seed::SeedSource;
use crate::mnemonic::{HDPath, generate_key};
use crate::core::chains::EthereumChainId;

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

impl WalletAccount {

    fn sign_tx_by_pk(&self, tx: Transaction, key: PrivateKey) -> Result<Vec<u8>, VaultError> {
        let chain_id = EthereumChainId::from(self.blockchain);
        tx.to_signed_raw(key, chain_id)
            .map_err(|e| VaultError::InvalidPrivateKey)
    }

    pub fn sign_tx(&self, tx: Transaction, password: Option<String>, vault: &VaultStorage) -> Result<Vec<u8>, VaultError> {
        let raw_tx = match &self.key {
            PKType::PrivateKeyRef(pk) => {
                let key = vault.keys().get(&pk)?;
                if password.is_none() {
                    return Err(VaultError::PasswordRequired);
                }
                let password = password.unwrap();
                let key = key.decrypt(password.as_str())?;
                let key = PrivateKey::try_from(key.as_slice())?;
                self.sign_tx_by_pk(tx, key)
            }
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(&seed.seed_id)?;
                match seed_details.source {
                    SeedSource::Bytes(bytes) => {
                        if password.is_none() {
                            return Err(VaultError::PasswordRequired);
                        }
                        let password = password.unwrap();
                        let seed_key = bytes.decrypt(password.as_str())?;
                        let hd_path = HDPath::try_from(seed.hd_path.as_str())?;
                        let key = generate_key(&hd_path, &seed_key)?;
                        self.sign_tx_by_pk(tx, key)
                    },
                    SeedSource::Ledger(ledger) => {
                        unimplemented!()
                    }
                }
            }
        };
        raw_tx
    }
}

#[cfg(test)]
mod tests {
    use crate::structs::wallet::{WalletAccount, PKType};
    use crate::core::chains::Blockchain;
    use uuid::Uuid;
    use crate::{Transaction, to_32bytes, PrivateKey, Address};
    use std::str::FromStr;
    use tempdir::TempDir;
    use crate::storage::vault::VaultStorage;
    use crate::structs::pk::{PrivateKeyHolder, PrivateKeyType, EthereumPk3};
    use crate::structs::crypto::Encrypted;
    use crate::structs::types::HasUuid;


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
}
