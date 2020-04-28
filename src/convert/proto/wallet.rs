use crate::convert::error::ConversionError;
use crate::{
    core::{chains::Blockchain, Address},
    proto::{
        address::{Address as proto_Address, Address_oneof_address_type as proto_AddressType},
        seed::SeedHD as proto_SeedHD,
        wallet::{
            Wallet as proto_Wallet,
            WalletEntry as proto_WalletEntry,
            WalletEntry_oneof_pk_type as proto_WalletEntryPkType,
            Reserved as proto_Reserved,
        },
        common::FileType as proto_FileType
    },
    structs::{
        seed::SeedRef,
        wallet::{PKType, Wallet, WalletEntry},
    },
    util::optional::none_if_empty,
};
use protobuf::{parse_from_bytes, Message};
use std::cmp;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use uuid::Uuid;
use crate::structs::wallet::ReservedPath;
use crate::hdwallet::bip32::HDPath;
use hdpath::StandardHDPath;

impl TryFrom<&proto_WalletEntry> for WalletEntry {
    type Error = ConversionError;

    fn try_from(value: &proto_WalletEntry) -> Result<Self, Self::Error> {
        let blockchain = Blockchain::try_from(value.get_blockchain_id())
            .map_err(|_| ConversionError::UnsupportedValue("blockchain_id".to_string()))?;
        let address = value.address.clone().into_option();
        let address = match &address {
            Some(a) => match &a.address_type {
                Some(address_type) => match address_type {
                    proto_AddressType::plain_address(a) => Some(Address::from_str(a.as_str())?),
                    _ => {
                        return Err(ConversionError::UnsupportedValue(
                            "address_type".to_string(),
                        ))
                    }
                },
                None => None,
            },
            None => None,
        };
        let key = match &value.pk_type {
            Some(pk_type) => match pk_type {
                proto_WalletEntryPkType::hd_path(seed) => {
                    let seed = SeedRef {
                        seed_id: Uuid::from_bytes(seed.get_seed_id()).map_err(|_| {
                            ConversionError::InvalidFieldValue("seed_id".to_string())
                        })?,
                        hd_path: StandardHDPath::try_from(seed.get_path()).map_err(|_| {
                            ConversionError::InvalidFieldValue("hd_path".to_string())
                        })?,
                    };
                    PKType::SeedHd(seed)
                }
                proto_WalletEntryPkType::pk_id(pk_id) => PKType::PrivateKeyRef(
                    Uuid::from_bytes(pk_id)
                        .map_err(|_| ConversionError::InvalidFieldValue("pk_id".to_string()))?,
                ),
            },
            None => return Err(ConversionError::FieldIsEmpty("pk_type".to_string())),
        };
        let id = value.get_id() as usize;
        let receive_disabled = value.get_receive_disabled();
        let result = WalletEntry {
            id,
            blockchain,
            address,
            key,
            receive_disabled,
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

        if value.address.is_some() {
            let address_str = value.address.unwrap().to_string();
            let mut address = proto_Address::new();
            address.set_plain_address(address_str.clone());
            result.set_address(address);
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
        result
    }
}

impl TryFrom<proto_Wallet> for Vec<ReservedPath> {
    type Error = ConversionError;

    fn try_from(value: proto_Wallet) -> Result<Self, Self::Error> {
        let mut result = Vec::with_capacity(value.hd_accounts.len());
        for r in value.hd_accounts.to_vec() {
            match Uuid::from_bytes(r.seed_id.as_slice()) {
                Ok(id) => {
                    result.push(ReservedPath {
                        seed_id: id,
                        account_id: r.account_id
                    })
                },
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
        let m = parse_from_bytes::<proto_Wallet>(value)?;
        let mut entries: Vec<WalletEntry> = Vec::new();
        for m in m.entries.iter() {
            let acc = WalletEntry::try_from(m)?;
            entries.push(acc);
        }
        let result = Wallet {
            id: Uuid::from_bytes(m.get_id())
                .map_err(|_| ConversionError::InvalidFieldValue("id".to_string()))?,
            label: none_if_empty(m.get_label()),
            entries,
            entry_seq: m.get_entry_seq() as usize,
            reserved: m.try_into()?,
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

        result
            .write_to_bytes()
            .map_err(|e| ConversionError::from(e))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        chains::Blockchain,
        core::Address,
        structs::{
            seed::SeedRef,
            wallet::{PKType, Wallet, WalletEntry},
        },
    };
    use std::convert::{TryFrom, TryInto};
    use std::str::FromStr;
    use uuid::Uuid;
    use crate::structs::wallet::ReservedPath;
    use hdpath::StandardHDPath;
    use crate::proto::{
        wallet::{
            Wallet as proto_Wallet,
            WalletEntry as proto_WalletEntry,
        },
        seed::{
            SeedHD as proto_SeedHD, HDPath as proto_HDPath
        }
    };
    use protobuf::{Message, parse_from_bytes, ProtobufEnum};
    use crate::convert::error::ConversionError;

    #[test]
    fn write_and_read_empty() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: None,
            entries: vec![],
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
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = parse_from_bytes::<proto_Wallet>(b.as_slice()).unwrap();
        assert_eq!(act.get_file_type().value(), 1);
        assert_eq!(Uuid::from_bytes(act.get_id()).unwrap(), Uuid::from_str("60eb04b5-1602-4e75-885f-076217ac5d0d").unwrap());
        assert_eq!(act.get_label(), "");
        assert_eq!(act.get_entries().len(), 0);
        assert_eq!(act.get_hd_accounts().len(), 0);
        assert_eq!(act.get_entry_seq(), 0);
    }

    #[test]
    fn write_and_read_wallet() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: Some("Test wallet 1".to_string()),
            entries: vec![WalletEntry {
                id: 0,
                blockchain: Blockchain::Ethereum,
                address: Some(
                    Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap(),
                ),
                key: PKType::PrivateKeyRef(Uuid::new_v4()),
                receive_disabled: false,
            }],
            entry_seq: 1,
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act, wallet);
    }

    #[test]
    fn write_and_read_wallet_wo_label() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: None,
            entries: vec![WalletEntry {
                id: 0,
                blockchain: Blockchain::Ethereum,
                address: Some(
                    Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap(),
                ),
                key: PKType::PrivateKeyRef(Uuid::new_v4()),
                receive_disabled: false,
            }],
            entry_seq: 1,
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
                address: Some(
                    Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap(),
                ),
                key: PKType::SeedHd(SeedRef {
                    seed_id: Uuid::from_str("351ef1f4-f1dd-4acb-9d8b-d7eec02b1da2").unwrap(),
                    hd_path: StandardHDPath::try_from("m/44'/60'/0'/0/0").unwrap(),
                }),
                receive_disabled: false,
            }],
            entry_seq: 1,
            reserved: vec![
                ReservedPath {
                    seed_id: Uuid::from_str("351ef1f4-f1dd-4acb-9d8b-d7eec02b1da2").unwrap(),
                    account_id: 0,
                }
            ],
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
                address: Some(
                    Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap(),
                ),
                key: PKType::SeedHd(SeedRef {
                    seed_id: Uuid::from_str("351ef1f4-f1dd-4acb-9d8b-d7eec02b1da2").unwrap(),
                    hd_path: StandardHDPath::try_from("m/44'/60'/0'/0/1").unwrap(),
                }),
                receive_disabled: true,
            }],
            entry_seq: 1,
            reserved: vec![
                ReservedPath {
                    seed_id: Uuid::from_str("351ef1f4-f1dd-4acb-9d8b-d7eec02b1da2").unwrap(),
                    account_id: 0,
                }
            ],
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
                account_id: 1
            }],
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act.reserved[0].seed_id.to_string(), "126d8ad4-d5a3-4b42-ba31-365cb5c34b5f");
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
                    key: PKType::SeedHd(
                        SeedRef {
                            seed_id: Uuid::from_str("126d8ad4-d5a3-4b42-ba31-365cb5c34b5f").unwrap(),
                            hd_path: StandardHDPath::try_from("m/44'/60'/0'/0/1").unwrap(),
                        }
                    ),
                    ..WalletEntry::default()
                },
                WalletEntry {
                    id: 1,
                    blockchain: Blockchain::Ethereum,
                    key: PKType::SeedHd(
                        SeedRef {
                            seed_id: Uuid::from_str("ad22b0da-12ae-4433-960a-755ad3a2558c").unwrap(),
                            hd_path: StandardHDPath::try_from("m/44'/60'/1'/0/1").unwrap(),
                        }
                    ),
                    ..WalletEntry::default()
                }
            ],
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act.reserved.len(), 2);
        assert_eq!(act.reserved[0].seed_id.to_string(), "126d8ad4-d5a3-4b42-ba31-365cb5c34b5f");
        assert_eq!(act.reserved[0].account_id, 0);
        assert_eq!(act.reserved[1].seed_id.to_string(), "ad22b0da-12ae-4433-960a-755ad3a2558c");
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

        assert_eq!(Err(ConversionError::InvalidFieldValue("hd_path".to_string())), wallet_act);
    }

}
