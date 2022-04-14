use crate::{
    blockchain::chains::Blockchain,
    convert::error::ConversionError,
    storage::vault::VaultStorage,
    error::VaultError,
    structs::{
        book::AddressRef,
        seed::{SeedRef, SeedSource},
        types::HasUuid,
    },
};
use chrono::{DateTime, Utc};
use hdpath::{StandardHDPath, AccountHDPath};
use regex::Regex;
use std::str::FromStr;
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EntryAddress<T> {
    pub address: T,
    pub hd_path: Option<StandardHDPath>,
    pub role: AddressRole,
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
    Default
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

impl ToString for AddressRole {
    fn to_string(&self) -> String {
        match self {
            AddressRole::Default => "default".to_string(),
            AddressRole::Change => "change".to_string(),
            AddressRole::Receive => "receive".to_string()
        }
    }
}

impl FromStr for AddressRole {
    type Err = ConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" => Ok(AddressRole::Default),
            "change" => Ok(AddressRole::Change),
            "receive" => Ok(AddressRole::Receive),
            _ => Err(ConversionError::UnsupportedValue(s.to_string()))
        }
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

    pub fn account_hd(&self) -> Option<AccountHDPath> {
        match &self.key {
            PKType::SeedHd(seed) => Some(AccountHDPath::from(&seed.hd_path)),
            PKType::PrivateKeyRef(_) => None
        }
    }

    pub fn get_addresses<T>(&self, role: AddressRole, start: u32, limit: u32) -> Result<Vec<EntryAddress<T>>, VaultError>
        where T: AddressFromPub<T> + AddressCast<T> {
        if limit == 0 {
            return Ok(vec![])
        }
        match &self.address {
            None => Ok(vec![]),
            Some(address) => match address {
                AddressRef::EthereumAddress(value) => match T::from_ethereum_address(value.clone()) {
                    Some(address) => Ok(vec![EntryAddress { hd_path: None, role: AddressRole::Default, address }]),
                    None => Ok(vec![])
                },
                AddressRef::BitcoinAddress(value) => match T::from_bitcoin_address(value.clone()) {
                    Some(address) => Ok(vec![EntryAddress { hd_path: None, role: AddressRole::Default, address }]),
                    None => Ok(vec![])
                },
                AddressRef::ExtendedPub(xpub) => {
                    let hd_path_base: Option<StandardHDPath>;
                    let xpub = if xpub.is_account() {
                        match role {
                            AddressRole::Receive => {
                                hd_path_base = self.account_hd()
                                    .map(|a| a.address_at(0, 0).unwrap());
                                xpub.for_receiving()?
                            },
                            AddressRole::Change => {
                                hd_path_base = self.account_hd()
                                    .map(|a| a.address_at(1, 0).unwrap());
                                xpub.for_change()?
                            },
                            AddressRole::Default => return Err(VaultError::PublicKeyUnavailable)
                        }
                    } else {
                        // if we have only index-level xpub we expect it to be use for all roles
                        if role != AddressRole::Default {
                            return Err(VaultError::PublicKeyUnavailable)
                        }
                        hd_path_base = None;
                        xpub.clone()
                    };
                    let addresses: Vec<EntryAddress<T>> = range(start, start + limit)
                        .map(|n|
                            xpub.get_address::<T>(n).ok().map(|a| EntryAddress {
                                address: a,
                                hd_path: hd_path_base.as_ref().map(|a|
                                    StandardHDPath::new(
                                        a.purpose().clone(),
                                        a.coin_type(),
                                        a.account(),
                                        a.change(),
                                        n,
                                    )),
                                role: role.clone(),
                            })
                        )
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
        storage::vault::VaultStorage,
        structs::{
            seed::{LedgerSource, Seed, SeedRef, SeedSource},
            wallet::{EntryId, PKType, Wallet, WalletEntry},
        },
        EthereumAddress,
    };
    use chrono::Utc;
    use hdpath::{AccountHDPath, StandardHDPath};
    use std::{convert::TryFrom, str::FromStr};
    use tempdir::TempDir;
    use uuid::Uuid;
    use crate::blockchain::bitcoin::{AddressType, XPub};
    use crate::storage::vault_bitcoin::get_address;
    use crate::structs::wallet::{AddressRole, EntryAddress};
    use bitcoin::Address;
    use crate::structs::book::AddressRef;
    use crate::convert::error::ConversionError;
    use crate::mnemonic::{Language, Mnemonic};

    #[test]
    fn encode_decode_role() {
        assert_eq!(
            Ok(AddressRole::Receive),
            AddressRole::from_str(AddressRole::Receive.to_string().as_str())
        );
        assert_eq!(
            Ok(AddressRole::Change),
            AddressRole::from_str(AddressRole::Change.to_string().as_str())
        );
        assert_eq!(
            Ok(AddressRole::Default),
            AddressRole::from_str(AddressRole::Default.to_string().as_str())
        );
    }

    #[test]
    fn fail_decode_invalid_role() {
        assert_eq!(
            Err(ConversionError::UnsupportedValue("hello".to_string())),
            AddressRole::from_str("hello")
        );
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
    fn get_xpub_addresses_bitcoin() {
        let phrase = Mnemonic::try_from(
            Language::English,
            "anchor badge zone antique book leader cupboard wolf confirm average unable nut tortoise dinner private",
        ).unwrap();
        let seed = phrase.seed(None);
        let xpub = get_address(&Blockchain::Bitcoin, AddressType::P2WPKH, 4, seed).unwrap();
        assert_eq!(
            "zpub6rebv42D4si3tnSFoZAtR1YjcpzJphTYzUB5eQkLtgGDMrzPjGZZwCx2q4vJntPb39EH1swwDkmUKR2hF9xbFm3icNCZiyywcTE32Axuxe3".to_string(),
            xpub.to_string()
        );

        let entry = WalletEntry {
            blockchain: Blockchain::Bitcoin,
            address: Some(AddressRef::ExtendedPub(xpub)),
            key: PKType::SeedHd(SeedRef {
                seed_id: Uuid::new_v4(),
                hd_path: StandardHDPath::from_str("m/84'/0'/4'/0/0").unwrap(),
            }),
            ..Default::default()
        };

        let act = entry.get_addresses::<Address>(AddressRole::Receive, 0, 5).unwrap();
        assert_eq!(
            vec![
                EntryAddress {
                    role: AddressRole::Receive,
                    address: Address::from_str("bc1qrezwju94ma8j6lgh9nzr7hx5fd6jek428pv699").unwrap(),
                    hd_path: Some(StandardHDPath::from_str("m/84'/0'/4'/0/0").unwrap()),
                },
                EntryAddress {
                    role: AddressRole::Receive,
                    address: Address::from_str("bc1q5urae4xldljrly5mjvendfsm8h84f2rzw5hqzs").unwrap(),
                    hd_path: Some(StandardHDPath::from_str("m/84'/0'/4'/0/1").unwrap()),
                },
                EntryAddress {
                    role: AddressRole::Receive,
                    address: Address::from_str("bc1q36ect6q9z2w7wxz7l6ajfgec7fhse448w4p3vg").unwrap(),
                    hd_path: Some(StandardHDPath::from_str("m/84'/0'/4'/0/2").unwrap()),
                },
                EntryAddress {
                    role: AddressRole::Receive,
                    address: Address::from_str("bc1qy9vk2xwwysg4l8uugcrkj7lwa89dz50vp4jsst").unwrap(),
                    hd_path: Some(StandardHDPath::from_str("m/84'/0'/4'/0/3").unwrap()),
                },
                EntryAddress {
                    role: AddressRole::Receive,
                    address: Address::from_str("bc1qjt668v40dhwm939749z0lagj267xq4me60cdgy").unwrap(),
                    hd_path: Some(StandardHDPath::from_str("m/84'/0'/4'/0/4").unwrap()),
                },
            ],
            act
        );

        // different address for change
        let act = entry.get_addresses::<Address>(AddressRole::Change, 0, 1).unwrap();
        assert_eq!(
            vec![
                EntryAddress {
                    role: AddressRole::Change,
                    address: Address::from_str("bc1qg625gty7hkx3gdp8j84y3jfmjj805fa8rqnjah").unwrap(),
                    hd_path: Some(StandardHDPath::from_str("m/84'/0'/4'/1/0").unwrap()),
                },
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
                EntryAddress {
                    address: EthereumAddress::from_str("0x7Bd9D156C6624b4D9a429cf81b91a9B500bDE2C7").unwrap(),
                    hd_path: None,
                    role: AddressRole::Default,
                }
            ],
            act
        );

        let act = entry.get_addresses::<EthereumAddress>(AddressRole::Change, 0, 1).unwrap();
        assert_eq!(
            vec![
                EntryAddress {
                    address: EthereumAddress::from_str("0x7Bd9D156C6624b4D9a429cf81b91a9B500bDE2C7").unwrap(),
                    hd_path: None,
                    role: AddressRole::Default,
                }
            ],
            act
        );
    }
}
