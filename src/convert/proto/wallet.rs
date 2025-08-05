use crate::{
    blockchain::chains::Blockchain,
    convert::error::ConversionError,
    proto::{
        common::FileType as proto_FileType,
        seed::SeedHD as proto_SeedHD,
        wallet::{
            Reserved as proto_Reserved,
            Wallet as proto_Wallet,
            WalletEntry as proto_WalletEntry,
            WalletEntry_oneof_pk_type as proto_WalletEntryPkType,
        },
    },
    structs::{
        seed::SeedRef,
        wallet::{PKType, ReservedPath, Wallet, WalletEntry},
    },
    util::none_if_empty,
};
use chrono::{TimeZone, Utc};
use hdpath::StandardHDPath;
use protobuf::Message;
use std::{
    cmp,
    convert::{TryFrom, TryInto},
};
use std::collections::HashSet;
use uuid::Uuid;

impl TryFrom<&proto_WalletEntry> for WalletEntry {
    type Error = ConversionError;

    fn try_from(value: &proto_WalletEntry) -> Result<Self, Self::Error> {
        let blockchain = Blockchain::try_from(value.get_blockchain_id())
            .map_err(|_| ConversionError::UnsupportedValue("blockchain_id".to_string()))?;
        let address = match &value.address.clone().into_option() {
            Some(address) => address.try_into()?,
            None => None,
        };
        let key = match &value.pk_type {
            Some(pk_type) => match pk_type {
                proto_WalletEntryPkType::hd_path(seed) => {
                    let seed = SeedRef {
                        seed_id: Uuid::from_slice(seed.get_seed_id()).map_err(|_| {
                            ConversionError::InvalidFieldValue("seed_id".to_string())
                        })?,
                        hd_path: StandardHDPath::try_from(seed.get_path()).map_err(|_| {
                            ConversionError::InvalidFieldValue("hd_path".to_string())
                        })?,
                    };
                    PKType::SeedHd(seed)
                }
                proto_WalletEntryPkType::pk_id(pk_id) => PKType::PrivateKeyRef(
                    Uuid::from_slice(pk_id)
                        .map_err(|_| ConversionError::InvalidFieldValue("pk_id".to_string()))?,
                ),
            },
            None => return Err(ConversionError::FieldIsEmpty("pk_type".to_string())),
        };
        let id = value.get_id() as usize;
        let receive_disabled = value.get_receive_disabled();
        let label = none_if_empty(value.get_label());
        let created_at = Utc.timestamp_millis_opt(value.get_created_at() as i64).unwrap();
        let result = WalletEntry {
            id,
            blockchain,
            address,
            key,
            receive_disabled,
            label,
            created_at,
        };
        Ok(result)
    }
}

// Write as Protobuf message
impl From<&WalletEntry> for proto_WalletEntry {
    fn from(value: &WalletEntry) -> Self {
        let mut result = proto_WalletEntry::default();
        result.set_id(value.id as u32);
        result.set_blockchain_id(value.blockchain.to_owned() as u32);
        result.set_receive_disabled(value.receive_disabled);
        if let Some(address) = &value.address {
            result.set_address(address.into())
        }
        if let Some(label) = &value.label {
            result.set_label(label.clone());
        }
        match &value.key {
            PKType::SeedHd(seed_ref) => {
                let mut seed_hd = proto_SeedHD::new();
                seed_hd.set_seed_id(seed_ref.seed_id.as_bytes().to_vec());
                seed_hd.set_path(seed_ref.hd_path.clone().into());
                result.set_hd_path(seed_hd);
            }
            PKType::PrivateKeyRef(addr) => {
                result.set_pk_id(addr.as_bytes().to_vec());
            }
        }
        result.set_created_at(value.created_at.timestamp_millis() as u64);
        result
    }
}

impl TryFrom<proto_Wallet> for Vec<ReservedPath> {
    type Error = ConversionError;

    fn try_from(value: proto_Wallet) -> Result<Self, Self::Error> {
        let mut result = Vec::with_capacity(value.hd_accounts.len());
        for r in value.hd_accounts.to_vec() {
            match Uuid::from_slice(r.seed_id.as_slice()) {
                Ok(id) => result.push(ReservedPath {
                    seed_id: id,
                    account_id: r.account_id,
                }),
                Err(_) => {}
            }
        }
        Ok(result)
    }
}

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for Wallet {
    type Error = ConversionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let m = proto_Wallet::parse_from_bytes(value)?;
        let mut active_addresses = HashSet::new();
        let mut entries: Vec<WalletEntry> = Vec::new();
        for m in m.entries.iter() {
            let acc = WalletEntry::try_from(m)?;

            // we want to have only uniq addresses in the Wallet to avoid any reference conflicts
            // when displaying it, calculating balance, etc.
            let uniq_address = if let Some(address) = &acc.address {
                active_addresses.insert((acc.blockchain, address.clone()))
            } else {
                true
            };
            if uniq_address {
                entries.push(acc);
            }
        }
        let created_at = Utc
            .timestamp_millis_opt(m.get_created_at() as i64)
            .single()
            .unwrap_or_else(|| Utc.timestamp_millis_opt(0).unwrap());
        let result = Wallet {
            id: Uuid::from_slice(m.get_id())
                .map_err(|_| ConversionError::InvalidFieldValue("id".to_string()))?,
            label: none_if_empty(m.get_label()),
            entries,
            entry_seq: m.get_entry_seq() as usize,
            reserved: m.try_into()?,
            created_at,
        };
        Ok(result)
    }
}

/// Read from Protobuf bytes
impl TryFrom<Vec<u8>> for Wallet {
    type Error = ConversionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Wallet::try_from(value.as_slice())
    }
}

/// Write as Protobuf bytes
impl TryFrom<Wallet> for Vec<u8> {
    type Error = ConversionError;

    fn try_from(value: Wallet) -> Result<Self, Self::Error> {
        let mut result = proto_Wallet::default();
        result.set_id(value.id.as_bytes().to_vec());
        result.set_file_type(proto_FileType::FILE_WALLET);
        if value.label.is_some() {
            result.set_label(value.label.unwrap());
        }

        let mut reserved = value.reserved.clone();

        for acc in &value.entries {
            //check if wallet has any seed-base entries that didn't reserve their entry_id
            if let PKType::SeedHd(seed) = &acc.key {
                if let Ok(account_id) = seed.get_account_id() {
                    let r = ReservedPath {
                        seed_id: seed.seed_id.clone(),
                        account_id,
                    };
                    if !reserved.contains(&r) {
                        //reserve current entry
                        reserved.push(r)
                    }
                }
            }
            result.entries.push(proto_WalletEntry::from(acc));
        }

        // Find max unused entry_id and remember entry seq value
        let max_entry_id = value.entries.iter().map(|a| a.id).max();
        let entry_seq = match max_entry_id {
            // If wallet has entries then entry_seq is at least the next number after current
            Some(id) => cmp::max(id + 1, value.entry_seq),
            // Otherwise just keep current seq value
            None => value.entry_seq,
        };
        result.set_entry_seq(entry_seq as u32);
        for r in reserved {
            let mut r_proto = proto_Reserved::new();
            r_proto.set_seed_id(r.seed_id.as_bytes().to_vec());
            r_proto.set_account_id(r.account_id);
            result.hd_accounts.push(r_proto);
        }
        result.set_created_at(value.created_at.timestamp_millis() as u64);

        result
            .write_to_bytes()
            .map_err(|e| ConversionError::from(e))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        blockchain::{bitcoin::XPub, EthereumAddress},
        chains::Blockchain,
        convert::error::ConversionError,
        proto::{
            seed::{HDPath as proto_HDPath, SeedHD as proto_SeedHD},
            wallet::{Wallet as proto_Wallet, WalletEntry as proto_WalletEntry},
        },
        structs::{
            book::AddressRef,
            seed::SeedRef,
            wallet::{PKType, ReservedPath, Wallet, WalletEntry},
        },
    };
    use chrono::{TimeZone, Utc};
    use hdpath::StandardHDPath;
    use protobuf::{Message, ProtobufEnum};
    use std::{
        convert::{TryFrom, TryInto},
        str::FromStr,
    };
    use uuid::Uuid;

    #[test]
    fn write_and_read_empty() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: None,
            entries: vec![],
            created_at: Utc.timestamp_millis_opt(0).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act.label, None);
        assert_eq!(act.entries.len(), 0);
        assert_eq!(act, wallet);
    }

    #[test]
    fn write_as_protobuf() {
        let wallet = Wallet {
            id: Uuid::from_str("60eb04b5-1602-4e75-885f-076217ac5d0d").unwrap(),
            label: None,
            entries: vec![],
            created_at: Utc.timestamp_millis_opt(1592624592679).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = proto_Wallet::parse_from_bytes(b.as_slice()).unwrap();
        assert_eq!(act.get_file_type().value(), 1);
        assert_eq!(
            Uuid::from_slice(act.get_id()).unwrap(),
            Uuid::from_str("60eb04b5-1602-4e75-885f-076217ac5d0d").unwrap()
        );
        assert_eq!(act.get_label(), "");
        assert_eq!(act.get_entries().len(), 0);
        assert_eq!(act.get_hd_accounts().len(), 0);
        assert_eq!(act.get_entry_seq(), 0);
        assert_eq!(act.get_created_at(), 1592624592679);
    }

    #[test]
    fn write_and_read_wallet() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: Some("Test wallet 1".to_string()),
            entries: vec![WalletEntry {
                id: 0,
                blockchain: Blockchain::Ethereum,
                address: Some(AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99")
                        .unwrap(),
                )),
                key: PKType::PrivateKeyRef(Uuid::new_v4()),
                created_at: Utc.timestamp_millis_opt(0).unwrap(),
                ..WalletEntry::default()
            }],
            entry_seq: 1,
            created_at: Utc.timestamp_millis_opt(0).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act, wallet);
    }

    #[test]
    fn write_and_read_wallet_bitcoin() {
        let seed_id = Uuid::new_v4();
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: Some("Test wallet 1".to_string()),
            entries: vec![WalletEntry {
                id: 0,
                blockchain: Blockchain::Bitcoin,
                address: Some(
                    AddressRef::ExtendedPub(
                        XPub::from_str("zpub6rxn6spLExVKZkzwQeytdBxDAuZk4KsdchwgHP9Ffi91CtvsnsigkP7ffGjn6KMsNyqcuwwh2DKTBVUrTidWJyrEUbctLKhrK3AT7Kyw4N8").unwrap()
                    ),
                ),
                key: PKType::SeedHd(SeedRef { seed_id, hd_path: StandardHDPath::try_from("m/84'/0'/1'/0/0").unwrap() }),
                created_at: Utc.timestamp_millis_opt(0).unwrap(),
                ..WalletEntry::default()
            }],
            entry_seq: 1,
            created_at: Utc.timestamp_millis_opt(0).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);

        let act = Wallet::try_from(b).unwrap();
        // reserves the account on save
        let mut exp = wallet.clone();
        exp.reserved = vec![ReservedPath {
            seed_id,
            account_id: 1,
        }];
        assert_eq!(act, exp);
    }

    #[test]
    fn write_and_read_wallet_wo_label() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: None,
            entries: vec![WalletEntry {
                id: 0,
                blockchain: Blockchain::Ethereum,
                address: Some(AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99")
                        .unwrap(),
                )),
                key: PKType::PrivateKeyRef(Uuid::new_v4()),
                created_at: Utc.timestamp_millis_opt(0).unwrap(),
                ..WalletEntry::default()
            }],
            entry_seq: 1,
            created_at: Utc.timestamp_millis_opt(0).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act, wallet);
    }

    #[test]
    fn write_and_read_wallet_w_seedref() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: None,
            entries: vec![WalletEntry {
                id: 0,
                blockchain: Blockchain::Ethereum,
                address: Some(AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99")
                        .unwrap(),
                )),
                key: PKType::SeedHd(SeedRef {
                    seed_id: Uuid::from_str("351ef1f4-f1dd-4acb-9d8b-d7eec02b1da2").unwrap(),
                    hd_path: StandardHDPath::try_from("m/44'/60'/0'/0/0").unwrap(),
                }),
                created_at: Utc.timestamp_millis_opt(0).unwrap(),
                ..WalletEntry::default()
            }],
            entry_seq: 1,
            reserved: vec![ReservedPath {
                seed_id: Uuid::from_str("351ef1f4-f1dd-4acb-9d8b-d7eec02b1da2").unwrap(),
                account_id: 0,
            }],
            created_at: Utc.timestamp_millis_opt(0).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act, wallet);
    }

    #[test]
    fn write_and_read_send_only_entry() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: None,
            entries: vec![WalletEntry {
                id: 0,
                blockchain: Blockchain::Ethereum,
                address: Some(AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99")
                        .unwrap(),
                )),
                key: PKType::SeedHd(SeedRef {
                    seed_id: Uuid::from_str("351ef1f4-f1dd-4acb-9d8b-d7eec02b1da2").unwrap(),
                    hd_path: StandardHDPath::try_from("m/44'/60'/0'/0/1").unwrap(),
                }),
                receive_disabled: true,
                created_at: Utc.timestamp_millis_opt(0).unwrap(),
                ..WalletEntry::default()
            }],
            entry_seq: 1,
            reserved: vec![ReservedPath {
                seed_id: Uuid::from_str("351ef1f4-f1dd-4acb-9d8b-d7eec02b1da2").unwrap(),
                account_id: 0,
            }],
            created_at: Utc.timestamp_millis_opt(0).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert!(act.entries[0].receive_disabled);
        assert_eq!(act, wallet);
    }

    #[test]
    fn write_and_read_reserved_hd() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            reserved: vec![ReservedPath {
                seed_id: Uuid::from_str("126d8ad4-d5a3-4b42-ba31-365cb5c34b5f").unwrap(),
                account_id: 1,
            }],
            created_at: Utc.timestamp_millis_opt(0).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(
            act.reserved[0].seed_id.to_string(),
            "126d8ad4-d5a3-4b42-ba31-365cb5c34b5f"
        );
        assert_eq!(act.reserved[0].account_id, 1);
        assert_eq!(act, wallet);
    }

    #[test]
    fn reserve_current_seed() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            reserved: vec![ReservedPath {
                seed_id: Uuid::from_str("126d8ad4-d5a3-4b42-ba31-365cb5c34b5f").unwrap(),
                account_id: 0,
            }],
            entries: vec![
                WalletEntry {
                    id: 0,
                    blockchain: Blockchain::Ethereum,
                    key: PKType::SeedHd(SeedRef {
                        seed_id: Uuid::from_str("126d8ad4-d5a3-4b42-ba31-365cb5c34b5f").unwrap(),
                        hd_path: StandardHDPath::try_from("m/44'/60'/0'/0/1").unwrap(),
                    }),
                    created_at: Utc.timestamp_millis_opt(0).unwrap(),
                    ..WalletEntry::default()
                },
                WalletEntry {
                    id: 1,
                    blockchain: Blockchain::Ethereum,
                    key: PKType::SeedHd(SeedRef {
                        seed_id: Uuid::from_str("ad22b0da-12ae-4433-960a-755ad3a2558c").unwrap(),
                        hd_path: StandardHDPath::try_from("m/44'/60'/1'/0/1").unwrap(),
                    }),
                    created_at: Utc.timestamp_millis_opt(0).unwrap(),
                    ..WalletEntry::default()
                },
            ],
            created_at: Utc.timestamp_millis_opt(0).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act.reserved.len(), 2);
        assert_eq!(
            act.reserved[0].seed_id.to_string(),
            "126d8ad4-d5a3-4b42-ba31-365cb5c34b5f"
        );
        assert_eq!(act.reserved[0].account_id, 0);
        assert_eq!(
            act.reserved[1].seed_id.to_string(),
            "ad22b0da-12ae-4433-960a-755ad3a2558c"
        );
        assert_eq!(act.reserved[1].account_id, 1);
    }

    #[test]
    fn should_not_read_entry_with_invalid_hd() {
        let mut pk = proto_SeedHD::default();
        pk.set_seed_id(Uuid::new_v4().as_bytes().to_vec());
        let mut hdpath = proto_HDPath::new();
        hdpath.set_purpose(44);
        hdpath.set_coin(60);
        hdpath.set_account(1);
        hdpath.set_change(0);
        hdpath.set_index(0x80000001); //hardened, it's not allowed
        pk.set_path(hdpath);

        let mut entry = proto_WalletEntry::default();
        entry.set_id(1);
        entry.set_blockchain_id(Blockchain::Ethereum as u32);
        entry.set_hd_path(pk);

        let mut wallet = proto_Wallet::default();
        wallet.set_id(Uuid::new_v4().as_bytes().to_vec());
        wallet.set_label("test".to_string());
        wallet.entries.push(entry);

        let bytes = wallet.write_to_bytes().unwrap();

        let wallet_act = Wallet::try_from(bytes);

        assert_eq!(
            Err(ConversionError::InvalidFieldValue("hd_path".to_string())),
            wallet_act
        );
    }

    #[test]
    fn write_and_read_label() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            reserved: vec![ReservedPath {
                seed_id: Uuid::from_str("126d8ad4-d5a3-4b42-ba31-365cb5c34b5f").unwrap(),
                account_id: 1,
            }],
            label: Some("Test entry".to_string()),
            created_at: Utc.timestamp_millis_opt(0).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act.label, Some("Test entry".to_string()));
        assert_eq!(act, wallet);
    }

    #[test]
    fn write_and_read_created_at() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            reserved: vec![ReservedPath {
                seed_id: Uuid::from_str("126d8ad4-d5a3-4b42-ba31-365cb5c34b5f").unwrap(),
                account_id: 1,
            }],
            label: None,
            created_at: Utc.timestamp_millis_opt(1592624407736).unwrap(),
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act.created_at.timestamp_millis(), 1592624407736);
        assert_eq!(act.created_at.to_rfc3339(), "2020-06-20T03:40:07.736+00:00");
    }

    #[test]
    fn ignore_big_created_at() {
        let mut m = proto_Wallet::new();
        m.set_created_at((i64::MAX as u64) + 100);
        m.set_id(Uuid::new_v4().as_bytes().to_vec());

        let buf = m.write_to_bytes().unwrap();
        let act = Wallet::try_from(buf).unwrap();
        assert_eq!(act.created_at.timestamp_millis(), 0);
    }
}
