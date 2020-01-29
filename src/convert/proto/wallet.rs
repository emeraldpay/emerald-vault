use crate::convert::error::ConversionError;
use crate::{
    core::{chains::Blockchain, Address},
    proto::{
        address::{Address as proto_Address, Address_oneof_address_type as proto_AddressType},
        seed::SeedHD as proto_SeedHD,
        wallet::{
            EthereumAddress as proto_EthereumAddress, Wallet as proto_Wallet,
            WalletAccount as proto_WalletAccount,
            WalletAccount_oneof_pk_type as proto_WalletAccountPkType,
        },
    },
    structs::{
        seed::SeedRef,
        wallet::{PKType, Wallet, WalletAccount},
    },
    util::optional::none_if_empty,
};
use protobuf::{parse_from_bytes, Message};
use std::cmp;
use std::convert::TryFrom;
use std::str::FromStr;
use uuid::Uuid;

impl TryFrom<&proto_WalletAccount> for WalletAccount {
    type Error = ConversionError;

    fn try_from(value: &proto_WalletAccount) -> Result<Self, Self::Error> {
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
                proto_WalletAccountPkType::hd_path(seed) => {
                    let seed = SeedRef {
                        seed_id: Uuid::from_str(seed.get_seed_id()).map_err(|_| {
                            ConversionError::InvalidFieldValue("seed_id".to_string())
                        })?,
                        hd_path: seed.path.clone(),
                    };
                    PKType::SeedHd(seed)
                }
                proto_WalletAccountPkType::ethereum(pk) => PKType::PrivateKeyRef(
                    Uuid::parse_str(pk.get_pk_id())
                        .map_err(|_| ConversionError::InvalidFieldValue("pk_id".to_string()))?,
                ),
                _ => return Err(ConversionError::UnsupportedValue("pk_type".to_string())),
            },
            None => return Err(ConversionError::FieldIsEmpty("pk_type".to_string())),
        };
        let id = value.get_id() as usize;
        let result = WalletAccount {
            id,
            blockchain,
            address,
            key,
        };
        Ok(result)
    }
}

// Write as Protobuf message
impl From<&WalletAccount> for proto_WalletAccount {
    fn from(value: &WalletAccount) -> Self {
        let mut result = proto_WalletAccount::default();
        result.set_id(value.id as u32);
        result.set_blockchain_id(value.blockchain.to_owned() as u32);

        let mut ethereum = proto_EthereumAddress::default();
        if value.address.is_some() {
            let address_str = value.address.unwrap().to_string();
            let mut address = proto_Address::new();
            address.set_plain_address(address_str.clone());
            result.set_address(address);
            ethereum.set_address(address_str);
        }
        match &value.key {
            PKType::SeedHd(seed_ref) => {
                let mut seed_hd = proto_SeedHD::new();
                seed_hd.set_seed_id(seed_ref.seed_id.to_string());
                seed_hd.set_path(seed_ref.hd_path.clone());
                result.set_hd_path(seed_hd);
            }
            PKType::PrivateKeyRef(addr) => {
                ethereum.set_pk_id(addr.to_string());
                result.set_ethereum(ethereum);
            }
        }
        result
    }
}

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for Wallet {
    type Error = ConversionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let m = parse_from_bytes::<proto_Wallet>(value)?;
        let mut accounts: Vec<WalletAccount> = Vec::new();
        for m in m.accounts.iter() {
            let acc = WalletAccount::try_from(m)?;
            accounts.push(acc);
        }
        let result = Wallet {
            id: Uuid::from_str(m.get_id())
                .map_err(|_| ConversionError::InvalidFieldValue("id".to_string()))?,
            label: none_if_empty(m.get_label()),
            accounts,
            account_seq: m.get_account_seq() as usize,
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
        result.set_id(value.id.to_string());
        if value.label.is_some() {
            result.set_label(value.label.unwrap());
        }
        let accounts = value
            .accounts
            .iter()
            .map(|acc| proto_WalletAccount::from(acc))
            .collect();
        result.set_accounts(accounts);

        // Find max unused account_id and remember account seq value
        let max_account_id = value.accounts.iter().map(|a| a.id).max();
        let account_seq = match max_account_id {
            // If wallet has accounts then account_seq is at least the next number after current
            Some(id) => cmp::max(id + 1, value.account_seq),
            // Otherwise just keep current seq value
            None => value.account_seq,
        };
        result.set_account_seq(account_seq as u32);

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
            wallet::{PKType, Wallet, WalletAccount},
        },
    };
    use std::convert::{TryFrom, TryInto};
    use std::str::FromStr;
    use uuid::Uuid;

    #[test]
    fn write_and_read_empty() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: None,
            accounts: vec![],
            ..Wallet::default()
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act.label, None);
        assert_eq!(act.accounts.len(), 0);
        assert_eq!(act, wallet);
    }

    #[test]
    fn write_and_read_wallet() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: Some("Test wallet 1".to_string()),
            accounts: vec![WalletAccount {
                id: 0,
                blockchain: Blockchain::Ethereum,
                address: Some(
                    Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap(),
                ),
                key: PKType::PrivateKeyRef(Uuid::new_v4()),
            }],
            account_seq: 1,
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
            accounts: vec![WalletAccount {
                id: 0,
                blockchain: Blockchain::Ethereum,
                address: Some(
                    Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap(),
                ),
                key: PKType::PrivateKeyRef(Uuid::new_v4()),
            }],
            account_seq: 1,
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
            accounts: vec![WalletAccount {
                id: 0,
                blockchain: Blockchain::Ethereum,
                address: Some(
                    Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap(),
                ),
                key: PKType::SeedHd(SeedRef {
                    seed_id: Uuid::new_v4(),
                    hd_path: "m/44'/60'/0'/0".to_string(),
                }),
            }],
            account_seq: 1,
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act, wallet);
    }
}
