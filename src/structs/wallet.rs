use crate::hdwallet::WManager;
use crate::{
    convert::{error::ConversionError, json::keyfile::EthereumJsonV3File},
    core::chains::{Blockchain, EthereumChainId},
    mnemonic::{generate_key},
    storage::{error::VaultError, vault::VaultStorage},
    structs::{
        seed::{SeedRef, SeedSource},
        types::HasUuid,
    },
    Address, PrivateKey, Transaction,
};
use hdpath::StandardHDPath;
use regex::Regex;
use std::str::FromStr;
use uuid::Uuid;
use std::time::SystemTime;
use chrono::{DateTime, Utc};
use std::convert::TryFrom;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Wallet {
    pub id: Uuid,
    pub label: Option<String>,
    pub entries: Vec<WalletEntry>,
    pub entry_seq: usize,
    pub reserved: Vec<ReservedPath>,
    ///creation date of the wallet
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReservedPath {
    pub seed_id: Uuid,
    pub account_id: u32,
}

///An entry of a Wallet. Contains actual configuration for an address, including private key.
///The address in fact maybe a sequence of address, for example on a HD Path. Also note that a
///single address may have multiple associated assets (for example ERC-20)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WalletEntry {
    ///Internal uniq id, for reference
    pub id: usize,
    ///Used assigned label
    pub label: Option<String>,
    ///Target blockchain
    pub blockchain: Blockchain,
    ///Public address, used for reference from UI. Actual address depends on the Private Key
    ///and maybe unavailable without password.
    pub address: Option<Address>,
    ///Private Kye
    pub key: PKType,
    ///If true the the entry should be used only for sending.
    ///It can be used for a legacy address, or for shadow address on opposite blockchain (ETH-ETC)
    ///to help recover funds mistakenly sent to a wrong chain.
    pub receive_disabled: bool,
    ///Creation date of the entry
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PKType {
    PrivateKeyRef(Uuid),
    SeedHd(SeedRef),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EntryId {
    pub wallet_id: Uuid,
    pub entry_id: usize,
}

impl HasUuid for Wallet {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl Wallet {
    pub fn get_entry(&self, id: usize) -> Result<WalletEntry, VaultError> {
        let found = self.entries.iter().find(|a| a.id == id);
        if found.is_none() {
            Err(VaultError::DataNotFound)
        } else {
            Ok(found.unwrap().clone())
        }
    }

    pub fn next_entry_id(&self) -> usize {
        let current = self.entries.iter().map(|a| a.id).max();
        let value = match current {
            Some(id) => id + 1,
            None => 0,
        };
        if value < self.entry_seq {
            self.entry_seq
        } else {
            value
        }
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Wallet {
            id: Uuid::new_v4(),
            label: None,
            entries: vec![],
            entry_seq: 0,
            reserved: vec![],
            created_at: Utc::now()
        }
    }
}

impl Default for WalletEntry {
    fn default() -> Self {
        WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: None,
            key: PKType::PrivateKeyRef(Uuid::nil()),
            receive_disabled: false,
            label: None,
            created_at: Utc::now()
        }
    }
}

lazy_static! {
    static ref ENTRY_ID_RE: Regex = Regex::new(
        r"^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})-([0-9]+)$"
    )
    .unwrap();
}

impl EntryId {
    pub fn from(wallet: &Wallet, entry: &WalletEntry) -> EntryId {
        EntryId {
            wallet_id: wallet.id.clone(),
            entry_id: entry.id,
        }
    }

    pub fn from_str(value: &str) -> Result<EntryId, VaultError> {
        let cap = ENTRY_ID_RE.captures(value);
        match cap {
            Some(cap) => Ok(EntryId {
                wallet_id: Uuid::from_str(cap.get(1).unwrap().as_str()).unwrap(),
                entry_id: cap.get(2).unwrap().as_str().parse::<usize>().unwrap(),
            }),
            None => Err(VaultError::from(ConversionError::InvalidArgument)),
        }
    }
}

impl ToString for EntryId {
    fn to_string(&self) -> String {
        return format!("{}-{}", self.wallet_id, self.entry_id);
    }
}

impl WalletEntry {
    pub fn get_full_id(&self, wallet: &Wallet) -> EntryId {
        EntryId::from(wallet, self)
    }

    fn sign_tx_by_pk(&self, tx: Transaction, key: PrivateKey) -> Result<Vec<u8>, VaultError> {
        let chain_id = EthereumChainId::from(self.blockchain);
        tx.to_signed_raw(key, chain_id)
            .map_err(|_| VaultError::InvalidPrivateKey)
    }

    fn sign_tx_with_hardware(
        &self,
        tx: Transaction,
        _: Uuid, //not used yet
        hd_path: StandardHDPath,
    ) -> Result<Vec<u8>, VaultError> {
        let hd_path = StandardHDPath::try_from(hd_path.to_string().as_str())
            .map_err(|_| VaultError::InvalidDataError("HDPath".to_string()))?;

        //TODO verify actual device, right now vault just uses a first currently available device
        let mut manager = WManager::new(Some(hd_path.to_bytes()))?;
        if manager.update(None).is_err() {
            return Err(VaultError::PrivateKeyUnavailable);
        }
        if manager.devices().is_empty() {
            return Err(VaultError::PrivateKeyUnavailable);
        }
        let chain_id = EthereumChainId::from(self.blockchain);
        let rlp = tx.to_rlp(Some(chain_id.as_chainid()));
        let fd = &manager.devices()[0].1;
        let sign = manager
            .sign_transaction(&fd, &rlp, None)
            .map_err(|_| VaultError::InvalidPrivateKey)?;
        let raw = tx.raw_from_sig(Some(chain_id.as_chainid()), &sign);
        //TODO verify that signature is from the entry's address
        Ok(raw)
    }

    fn is_hardware(&self, vault: &VaultStorage) -> Result<bool, VaultError> {
        match &self.key {
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(seed.seed_id)?;
                match seed_details.source {
                    SeedSource::Ledger(_) => Ok(true),
                    SeedSource::Bytes(_) => Ok(false),
                }
            }
            PKType::PrivateKeyRef(_) => Ok(false),
        }
    }

    pub fn sign_tx(
        &self,
        tx: Transaction,
        password: Option<String>,
        vault: &VaultStorage,
    ) -> Result<Vec<u8>, VaultError> {
        if self.is_hardware(vault)? {
            return match &self.key {
                PKType::SeedHd(seed) => {
                    Ok(self.sign_tx_with_hardware(tx, seed.seed_id, seed.hd_path.clone())?)
                }
                _ => Err(VaultError::UnsupportedDataError("NOT_SEED".to_string())),
            };
        }
        // Continue with using a key stored in the vault, it's always encrypted with a password, so it's required
        if password.is_none() {
            return Err(VaultError::PasswordRequired);
        }
        let key = self.export_pk(password.unwrap(), vault)?;
        self.sign_tx_by_pk(tx, key)
    }

    pub fn export_pk(
        &self,
        password: String,
        vault: &VaultStorage,
    ) -> Result<PrivateKey, VaultError> {
        match &self.key {
            PKType::PrivateKeyRef(pk) => {
                let key = vault.keys().get(pk.clone())?;
                let key = key.decrypt(password.as_str())?;
                PrivateKey::try_from(key.as_slice()).map_err(|_| VaultError::InvalidPrivateKey)
            }
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(seed.seed_id.clone())?;
                match seed_details.source {
                    SeedSource::Bytes(bytes) => {
                        let seed_key = bytes.decrypt(password.as_str())?;
                        let hd_path = StandardHDPath::try_from(seed.hd_path.to_string().as_str())?;
                        generate_key(&hd_path, &seed_key).map_err(|_| VaultError::InvalidPrivateKey)
                    }
                    SeedSource::Ledger(_) => Err(VaultError::PrivateKeyUnavailable),
                }
            }
        }
    }

    pub fn export_web3(
        &self,
        password: Option<String>,
        vault: &VaultStorage,
    ) -> Result<EthereumJsonV3File, VaultError> {
        let label = self.label.clone();
        match &self.key {
            PKType::PrivateKeyRef(pk) => {
                let key = vault.keys().get(pk.clone())?;
                EthereumJsonV3File::from_wallet(label, &key)
                    .map_err(|_| VaultError::InvalidPrivateKey)
            }
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(seed.seed_id.clone())?;
                match seed_details.source {
                    SeedSource::Bytes(bytes) => {
                        if password.is_none() {
                            return Err(VaultError::PasswordRequired);
                        }
                        let password = password.unwrap();
                        let seed_key = bytes.decrypt(password.as_str())?;
                        let hd_path = StandardHDPath::try_from(seed.hd_path.to_string().as_str())?;
                        let key = generate_key(&hd_path, &seed_key)
                            .map_err(|_| VaultError::InvalidPrivateKey)?;
                        EthereumJsonV3File::from_pk(label, key, password)
                            .map_err(|_| VaultError::InvalidPrivateKey)
                    }
                    SeedSource::Ledger(_) => Err(VaultError::PrivateKeyUnavailable),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::core::chains::Blockchain;
    use crate::hdwallet::test_commons::{is_ledger_enabled, read_test_txes};
    use crate::storage::vault::VaultStorage;
    use crate::structs::crypto::Encrypted;
    use crate::structs::pk::{EthereumPk3, PrivateKeyHolder, PrivateKeyType};
    use crate::structs::seed::{LedgerSource, Seed, SeedRef, SeedSource};
    use crate::structs::types::HasUuid;
    use crate::structs::wallet::{EntryId, PKType, Wallet, WalletEntry};
    use crate::{to_32bytes, Address, PrivateKey, ToHex, Transaction};
    use hdpath::StandardHDPath;
    use std::convert::TryFrom;
    use std::str::FromStr;
    use tempdir::TempDir;
    use uuid::Uuid;
    use chrono::Utc;

    #[test]
    fn sign_erc20_approve() {
        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            key: PKType::PrivateKeyRef(Uuid::default()), // not used by the test
            ..WalletEntry::default()
        };
        let tx = Transaction {
            nonce: 1,
            gas_price: to_32bytes("04a817c800"),
            gas_limit: 21000,
            to: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            value: to_32bytes("0de0b6b3a7640000"),
            data: hex::decode("095ea7b300000000000000000000000036a8ce9b0b86361a02070e4303d5e24d6c63b3f10000000000000000000000000000000000000000033b2e3c9fd0803ce8000000").unwrap(),
        };
        let key = PrivateKey::from_str(
            "0x7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
        )
        .unwrap();
        let act = entry.sign_tx_by_pk(tx, key).unwrap();
        assert_eq!(
            hex::encode(act),
            "f8b1018504a817c80082520894008aeeda4d805471df9b2a5b0f38a0c3bcba786b880de0b6b3a7640000b844095ea7b300000000000000000000000036a8ce9b0b86361a02070e4303d5e24d6c63b3f10000000000000000000000000000000000000000033b2e3c9fd0803ce800000026a08675b401448f7a82e8738e35fa09fb2e2a2acaa83caaa5d81abadfa99f4d174ca063b2e9d977a4d6c4a41492b72b0d9933d835ddfdaf299fde6327389485db04c1"
        )
    }

    #[test]
    fn sign_with_provided_pk() {
        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            key: PKType::PrivateKeyRef(Uuid::default()), // not used by the test
            ..WalletEntry::default()
        };
        let tx = Transaction {
            nonce: 1,
            gas_price: to_32bytes("04a817c800"),
            gas_limit: 21000,
            to: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            value: to_32bytes("0de0b6b3a7640000"),
            data: vec![],
        };
        let key = PrivateKey::from_str(
            "0x7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
        )
        .unwrap();
        let act = entry.sign_tx_by_pk(tx, key).unwrap();
        assert_eq!(
            hex::encode(act),
            "f86c018504a817c80082520894008aeeda4d805471df9b2a5b0f38a0c3bcba786b880de0b6b3a76400008026a0d478c7abb05f2cf1c1c118f7f919bc11149b3b2e8b6ac78c5517d6b74aeedcb3a06f0f26ceab9e999b7357087ca1b20f214e0aea58198ace9ee76ff8abe707c9a2"
        )
    }

    #[test]
    fn sign_with_stored_pk() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let raw_pk =
            hex::decode("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let key = PrivateKeyHolder {
            id: Uuid::new_v4(),
            pk: PrivateKeyType::EthereumPk(EthereumPk3 {
                address: Some(
                    Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
                ),
                key: Encrypted::encrypt(raw_pk, "testtest").unwrap(),
            }),
            created_at: Utc::now(),
        };
        let key_id = key.get_id();
        vault.keys().add(key).expect("Key not added");

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            key: PKType::PrivateKeyRef(key_id),
            ..WalletEntry::default()
        };
        let tx = Transaction {
            nonce: 1,
            gas_price: to_32bytes("04a817c800"),
            gas_limit: 21000,
            to: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            value: to_32bytes("0de0b6b3a7640000"),
            data: vec![],
        };

        let act = entry
            .sign_tx(tx, Some("testtest".to_string()), &vault)
            .unwrap();
        assert_eq!(
            hex::encode(act),
            "f86c018504a817c80082520894008aeeda4d805471df9b2a5b0f38a0c3bcba786b880de0b6b3a76400008026a0d478c7abb05f2cf1c1c118f7f919bc11149b3b2e8b6ac78c5517d6b74aeedcb3a06f0f26ceab9e999b7357087ca1b20f214e0aea58198ace9ee76ff8abe707c9a2"
        )
    }

    #[test]
    fn export_stored_pk() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let raw_pk =
            hex::decode("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let key = PrivateKeyHolder {
            id: Uuid::new_v4(),
            pk: PrivateKeyType::EthereumPk(EthereumPk3 {
                address: Some(
                    Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
                ),
                key: Encrypted::encrypt(raw_pk, "testtest").unwrap(),
            }),
            created_at: Utc::now(),
        };
        let key_id = vault.keys().add(key).unwrap();

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(Address::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            key: PKType::PrivateKeyRef(key_id),
            ..WalletEntry::default()
        };

        let pk = entry.export_pk("testtest".to_string(), &vault).unwrap();
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
                "test1234",
            ).unwrap(),
            label: None,
            created_at: Utc::now(),
        };
        let seed_id = vault.seeds().add(seed).unwrap();

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: None, //0xC27fBF02FB577683593b1114180CA6E2c88510A0
            key: PKType::SeedHd(SeedRef {
                seed_id,
                hd_path: StandardHDPath::try_from("m/44'/60'/2'/0/52").unwrap(),
            }),
            ..WalletEntry::default()
        };

        let pk = entry.export_pk("test1234".to_string(), &vault).unwrap();
        assert_eq!(
            pk.to_hex(),
            "62a54ec79949cf6eb3bec6d67a3cd5fab835899f80c99785b73e8cd2ae9cfadb"
        )
    }

    #[test]
    fn create_and_access_ledger_seed() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let seed = Seed {
            id: Uuid::new_v4(),
            source: SeedSource::Ledger(LedgerSource {
                fingerprints: vec![],
            }),
            label: None,
            created_at: Utc::now(),
        };
        let seed_id = vault.seeds().add(seed).unwrap();

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::EthereumClassic,
            address: None,
            key: PKType::SeedHd(SeedRef {
                seed_id,
                hd_path: StandardHDPath::try_from("m/44'/60'/160720'/0/0").unwrap(),
            }),
            ..WalletEntry::default()
        };

        let wallet = Wallet {
            entries: vec![entry],
            ..Wallet::default()
        };

        let wallet_id = vault.wallets().add(wallet).unwrap();

        let wallet_act = vault.wallets().get(wallet_id).unwrap();
        assert_eq!(wallet_act.entries.len(), 1);
        assert_eq!(wallet_act.entries[0].id, 0);
        let entry_act = wallet_act.entries[0].clone();
        let seed_ref = match entry_act.key {
            PKType::SeedHd(x) => x,
            _ => panic!("Not Seed HDPath"),
        };
        assert_eq!(
            seed_ref.hd_path.to_string(),
            "m/44'/60'/160720'/0/0".to_string()
        );
        assert_eq!(seed_ref.seed_id, seed_id);

        let seed_act = vault.seeds().get(seed_id).unwrap();
        match seed_act.source {
            SeedSource::Ledger(x) => x,
            _ => panic!("Not ledger"),
        };
    }

    #[test]
    fn parse_valid_entry_id() {
        let act = EntryId::from_str("94d70ee7-1657-442e-af87-0210e985f29e-1");
        assert!(act.is_ok());
        let act = act.unwrap();
        assert_eq!(1, act.entry_id);
        assert_eq!(
            Uuid::from_str("94d70ee7-1657-442e-af87-0210e985f29e").unwrap(),
            act.wallet_id
        );
    }

    #[test]
    fn sign_tx_with_ledger() {
        if !is_ledger_enabled() {
            warn!("Ledger test is disabled");
            return;
        }

        let test_txes = read_test_txes();
        let exp = &test_txes[0];

        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let seed = Seed {
            id: Uuid::new_v4(),
            source: SeedSource::Ledger(LedgerSource {
                fingerprints: vec![],
            }),
            label: None,
            created_at: Utc::now(),
        };
        let seed_id = vault.seeds().add(seed).unwrap();

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::EthereumClassic,
            address: None,
            key: PKType::SeedHd(SeedRef {
                seed_id,
                hd_path: StandardHDPath::try_from("m/44'/60'/160720'/0/0").unwrap(),
            }),
            ..WalletEntry::default()
        };

        let tx = Transaction {
            nonce: 0,
            gas_price: to_32bytes("04e3b29200"),
            gas_limit: 21000,
            to: Some(Address::from_str("0x78296F1058dD49C5D6500855F59094F0a2876397").unwrap()),
            value: to_32bytes("0de0b6b3a7640000"),
            data: vec![],
        };

        let signed = entry.sign_tx(tx, None, &vault).unwrap();
        let signed = hex::encode(signed);
        assert!(signed.starts_with(
            "f86d80\
             85\
             04e3b29200\
             82\
             5208\
             94\
             78296f1058dd49c5d6500855f59094f0a2876397\
             88\
             0de0b6b3a7640000\
             80\
             81\
             9d\
             a0"
        ));

        assert_eq!(exp.raw, signed);
    }
}
