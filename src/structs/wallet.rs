use crate::{
    blockchain::chains::{Blockchain, EthereumChainId},
    convert::{error::ConversionError, json::keyfile::EthereumJsonV3File},
    hdwallet::WManager,
    mnemonic::generate_key,
    storage::{error::VaultError, vault::VaultStorage},
    structs::{
        seed::{SeedRef, SeedSource},
        types::HasUuid,
    },
    EthereumAddress,
    EthereumPrivateKey,
    EthereumTransaction,
};
use chrono::{DateTime, Utc};
use hdpath::StandardHDPath;
use regex::Regex;
use std::{convert::TryFrom, str::FromStr};
use uuid::Uuid;

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
    pub address: Option<EthereumAddress>,
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
            created_at: Utc::now(),
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
            created_at: Utc::now(),
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
}

#[cfg(test)]
mod tests {
    use crate::{
        blockchain::chains::Blockchain,
        hdwallet::test_commons::{is_ledger_enabled, read_test_txes},
        storage::vault::VaultStorage,
        structs::{
            crypto::Encrypted,
            pk::{EthereumPk3, PrivateKeyHolder, PrivateKeyType},
            seed::{LedgerSource, Seed, SeedRef, SeedSource},
            types::HasUuid,
            wallet::{EntryId, PKType, Wallet, WalletEntry},
        },
        to_32bytes,
        EthereumAddress,
        EthereumPrivateKey,
        EthereumTransaction,
    };
    use chrono::Utc;
    use hdpath::StandardHDPath;
    use std::{convert::TryFrom, str::FromStr};
    use tempdir::TempDir;
    use uuid::Uuid;

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
}
