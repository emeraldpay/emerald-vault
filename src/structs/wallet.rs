use crate::{
    blockchain::chains::Blockchain,
    convert::error::ConversionError,
    storage::{error::VaultError, vault::VaultStorage},
    structs::{
        book::AddressRef,
        seed::{SeedRef, SeedSource},
        types::HasUuid,
    },
};
use bitcoin::util::bip32::ExtendedPubKey;
use chrono::{DateTime, Utc};
use hdpath::StandardHDPath;
use regex::Regex;
use std::{convert::TryFrom, str::FromStr};
use uuid::Uuid;
use num::range;
use crate::blockchain::addresses::{AddressFromPub, AddressCast};

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
    pub address: Option<AddressRef>,
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AddressRole {
    Receive,
    Change,
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

ord_by_date_id!(Wallet);

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

    pub fn is_hardware(&self, vault: &VaultStorage) -> Result<bool, VaultError> {
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

    pub fn get_addresses<T>(&self, role: AddressRole, start: u32, limit: u32) -> Result<Vec<T>, VaultError>
        where T: AddressFromPub<T> + AddressCast<T>, {
        if limit == 0 {
            return Ok(vec![])
        }
        match &self.address {
            None => Ok(vec![]),
            Some(address) => match address {
                AddressRef::EthereumAddress(value) => match T::from_ethereum_address(value.clone()) {
                    Some(address) => Ok(vec![address]),
                    None => Ok(vec![])
                },
                AddressRef::BitcoinAddress(value) => match T::from_bitcoin_address(value.clone()) {
                    Some(address) => Ok(vec![address]),
                    None => Ok(vec![])
                },
                AddressRef::ExtendedPub(xpub) => {
                    let xpub = if xpub.is_account() {
                        match role {
                            AddressRole::Receive => xpub.for_receiving()?,
                            AddressRole::Change => xpub.for_change()?
                        }
                    } else {
                        // if we have only index-level xpub we expect it to be use for all roles
                        xpub.clone()
                    };
                    let addresses: Vec<T> = range(start, start + limit)
                        .map(|n| xpub.get_address::<T>(n).ok())
                        .filter(|a| a.is_some())
                        .map(|a| a.unwrap())
                        .collect();
                    Ok(addresses)
                },
            }
        }
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
    use crate::blockchain::bitcoin::XPub;
    use crate::structs::wallet::AddressRole;
    use bitcoin::Address;
    use crate::structs::book::AddressRef;

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
    fn get_xpub_addresses_bitcoin() {
        let entry = WalletEntry {
            blockchain: Blockchain::Bitcoin,
            address: Some(AddressRef::ExtendedPub(
                // seed: anchor badge zone antique book leader cupboard wolf confirm average unable nut tortoise dinner private
                XPub::from_str("zpub6rebv42D4si3ibWtrRoeS3qvEaRWBuLfwq1SXZt6UMVU9CH8snBWeFFMSMvWsv5WFGVRhqr8gg2AR751SrKteeX9bq57HbTyQvqPznSpZex").unwrap()
            )),
            ..Default::default()
        };

        let act = entry.get_addresses::<Address>(AddressRole::Receive, 0, 5).unwrap();
        assert_eq!(
            vec![
                Address::from_str("bc1q8redwn9d9qr0nkp7ah367u56ufxjprf0lvp7an").unwrap(),
                Address::from_str("bc1q8lv69l5lnnpals79jqn78a3fy2eh8t9uls828y").unwrap(),
                Address::from_str("bc1q0pat93taakyswlt8gsxsru3a3x6e5k59arukmu").unwrap(),
                Address::from_str("bc1q4zxhcd25qqpxrdrf6d3p0qtg3vcjavajujw8rd").unwrap(),
                Address::from_str("bc1qzzve7js08mhsewg2jy6kkkj7fs298k9kz2snhs").unwrap(),
            ],
            act
        );

        // different address for change
        let act = entry.get_addresses::<Address>(AddressRole::Change, 0, 1).unwrap();
        assert_eq!(
            vec![
                Address::from_str("bc1q07937xm8m57yg9kq5u5569ajcvzgptlr42g8za").unwrap(),
            ],
            act
        );
    }

    #[test]
    fn get_std_addresses_ethereum() {
        let entry = WalletEntry {
            blockchain: Blockchain::Ethereum,
            address: Some(AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x7Bd9D156C6624b4D9a429cf81b91a9B500bDE2C7").unwrap()
            )),
            ..Default::default()
        };

        let act = entry.get_addresses::<EthereumAddress>(AddressRole::Receive, 0, 1).unwrap();
        assert_eq!(
            vec![
                EthereumAddress::from_str("0x7Bd9D156C6624b4D9a429cf81b91a9B500bDE2C7").unwrap(),
            ],
            act
        );

        let act = entry.get_addresses::<EthereumAddress>(AddressRole::Change, 0, 1).unwrap();
        assert_eq!(
            vec![
                EthereumAddress::from_str("0x7Bd9D156C6624b4D9a429cf81b91a9B500bDE2C7").unwrap(),
            ],
            act
        );
    }
}
