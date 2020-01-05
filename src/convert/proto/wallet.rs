use uuid::Uuid;
use std::convert::TryFrom;
use protobuf::{parse_from_bytes, Message};
use std::str::FromStr;
use crate::{
    structs::{
        seed::SeedRef,
        wallet::{WalletAccount, Wallet, PKType}
    },
    util::optional::none_if_empty,
    storage::error::VaultError,
    core::{
        chains::{Blockchain},
        Address
    },
    proto::{
        wallet::{
            Wallet as proto_Wallet,
            WalletAccount as proto_WalletAccount,
            WalletAccount_oneof_pk_type as proto_WalletAccountPkType,
            EthereumAddress as proto_EthereumAddress
        },
        seed::{
            SeedHD as proto_SeedHD
        },
        address::{
            Address as proto_Address,
            Address_oneof_address_type as proto_AddressType
        }
    },
};

impl TryFrom<&proto_WalletAccount> for WalletAccount {
    type Error = VaultError;

    fn try_from(value: &proto_WalletAccount) -> Result<Self, Self::Error> {
        let blockchain = Blockchain::try_from(value.get_blockchain_id())
            .map_err(|_| VaultError::UnsupportedDataError(format!("Unsupported asset: {}", value.get_blockchain_id())))?;
        let address = value.address.clone().into_option();
        let address = match &address {
            Some(a) => match &a.address_type {
                Some(address_type) => match address_type {
                    proto_AddressType::plain_address(a) => Some(Address::from_str(a.as_str())?),
                    _ => return Err(VaultError::UnsupportedDataError("Only single type of address is supported".to_string()))
                },
                None => None
            },
            None => None
        };
        let key = match &value.pk_type {
            Some(pk_type) => match pk_type {
                proto_WalletAccountPkType::hd_path(seed) => {
                    let seed = SeedRef {
                        seed_id: Uuid::from_str(seed.get_seed_id())?,
                        hd_path: seed.path.clone()
                    };
                    PKType::SeedHd(seed)
                },
                proto_WalletAccountPkType::ethereum(pk) => {
                    PKType::PrivateKeyRef(Uuid::parse_str(pk.get_pk_id())?)
                },
                _ => return Err(VaultError::UnsupportedDataError("Unsupported type of PrivateKey".to_string()))
            },
            None => return Err(VaultError::UnsupportedDataError("PrivateKey is not set".to_string()))
        };
        let id = value.get_id() as usize;
        let result = WalletAccount {
            id,
            blockchain,
            address,
            key
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
    type Error = VaultError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let m = parse_from_bytes::<proto_Wallet>(value)?;
        let mut accounts: Vec<WalletAccount> = Vec::new();
        for m in m.accounts.iter() {
            let acc = WalletAccount::try_from(m)?;
            accounts.push(acc);
        }
        let result = Wallet {
            id: Uuid::from_str(m.get_id())?,
            label: none_if_empty(m.get_label()),
            accounts
        };
        Ok(result)
    }
}

/// Read from Protobuf bytes
impl TryFrom<Vec<u8>> for Wallet {
    type Error = VaultError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Wallet::try_from(value.as_slice())
    }
}

/// Write as Protobuf bytes
impl TryFrom<Wallet> for Vec<u8> {
    type Error = VaultError;

    fn try_from(value: Wallet) -> Result<Self, Self::Error> {
        let mut result = proto_Wallet::default();
        result.set_id(value.id.to_string());
        if value.label.is_some() {
            result.set_label(value.label.unwrap());
        }
        let accounts = value.accounts.iter()
            .map(|acc| proto_WalletAccount::from(acc))
            .collect();
        result.set_accounts(accounts);

        result.write_to_bytes()
            .map_err(|e| VaultError::from(e))
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;
    use std::str::FromStr;
    use std::convert::{TryInto, TryFrom};
    use crate::{
        chains::Blockchain,
        core::Address,
        structs::{
            wallet::{
                Wallet, WalletAccount, PKType
            },
            seed::SeedRef
        }
    };

    #[test]
    fn write_and_read_wallet() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: Some("Test wallet 1".to_string()),
            accounts: vec![
                WalletAccount {
                    id: 0,
                    blockchain: Blockchain::Ethereum,
                    address: Some(Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap()),
                    key: PKType::PrivateKeyRef(Uuid::new_v4())
                }
            ]
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
            accounts: vec![
                WalletAccount {
                    id: 0,
                    blockchain: Blockchain::Ethereum,
                    address: Some(Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap()),
                    key: PKType::PrivateKeyRef(Uuid::new_v4())
                }
            ]
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
            accounts: vec![
                WalletAccount {
                    id: 0,
                    blockchain: Blockchain::Ethereum,
                    address: Some(Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap()),
                    key: PKType::SeedHd(SeedRef {
                        seed_id: Uuid::new_v4(),
                        hd_path: "m/44'/60'/0'/0".to_string()
                    })
                }
            ]
        };

        let b: Vec<u8> = wallet.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = Wallet::try_from(b).unwrap();
        assert_eq!(act, wallet);
    }

}
