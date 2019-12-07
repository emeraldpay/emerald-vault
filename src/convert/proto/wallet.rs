use uuid::Uuid;
use std::convert::TryFrom;
use protobuf::{parse_from_bytes, Message};
use std::str::FromStr;
use crate::proto::{
    wallet::{
        Wallet as proto_Wallet,
        WalletAccount as proto_WalletAccount,
        EthereumAddress as proto_EthereumAddress
    }
};
use crate::core::Address;
use crate::core::chains::{Blockchain, EthereumChainId};
use crate::storage::error::VaultError;
use crate::util::optional::none_if_empty;
use crate::convert::proto::types::HasUuid;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Wallet {
    pub id: Uuid,
    pub label: Option<String>,
    pub accounts: Vec<WalletAccount>
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WalletAccount {
    pub blockchain: Blockchain,
    pub address: AddressType
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AddressType {
    Ethereum(EthereumAddress)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EthereumAddress {
    pub address: Option<Address>,
    pub key_id: Uuid
}

impl HasUuid for Wallet {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl HasUuid for WalletAccount {
    fn get_id(&self) -> Uuid {
        match &self.address {
            AddressType::Ethereum(e) => e.key_id
        }
    }
}

impl TryFrom<&proto_WalletAccount> for WalletAccount {
    type Error = VaultError;

    fn try_from(value: &proto_WalletAccount) -> Result<Self, Self::Error> {
        let blockchain = Blockchain::try_from(value.get_blockchain_id())
            .map_err(|_| VaultError::UnsupportedDataError(format!("Unsupported asset: {}", value.get_blockchain_id())))?;
        let address = if value.has_ethereum() {
            let address = match none_if_empty(value.get_ethereum().address.as_str()) {
                Some(s) => {
                    let x = Address::from_str(s.as_str())?;
                    Some(x)
                },
                None => None
            };
            AddressType::Ethereum(EthereumAddress {
                address,
                key_id: Uuid::parse_str(value.get_ethereum().get_pk_id())?
            })
        } else {
            return Err(VaultError::UnsupportedDataError("Only ethereum type of address is supported".to_string()))
        };
        let result = WalletAccount {
            blockchain,
            address
        };
        Ok(result)
    }
}

// Write as Protobuf message
impl From<&WalletAccount> for proto_WalletAccount {

    fn from(value: &WalletAccount) -> Self {
        let mut result = proto_WalletAccount::default();
        result.set_blockchain_id(value.blockchain.to_owned() as u32);

        let mut ethereum = proto_EthereumAddress::default();
        match &value.address {
            AddressType::Ethereum(addr) => {
                if addr.address.is_some() {
                    ethereum.set_address(addr.address.unwrap().to_string());
                }
                ethereum.set_pk_id(addr.key_id.to_string());
            }
        }
        result.set_ethereum(ethereum);
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
    use crate::convert::proto::wallet::{
        Wallet, WalletAccount, AddressType, EthereumAddress
    };
    use uuid::Uuid;
    use crate::core::Address;
    use std::str::FromStr;
    use std::convert::{TryInto, TryFrom};
    use crate::chains::Blockchain;

    #[test]
    fn write_and_read_wallet() {
        let wallet = Wallet {
            id: Uuid::new_v4(),
            label: Some("Test wallet 1".to_string()),
            accounts: vec![
                WalletAccount {
                    blockchain: Blockchain::Ethereum,
                    address: AddressType::Ethereum(EthereumAddress {
                        address: Some(Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap()),
                        key_id: Uuid::new_v4()
                    })
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
                    blockchain: Blockchain::Ethereum,
                    address: AddressType::Ethereum(EthereumAddress {
                        address: Some(Address::from_str("0x6412c428fc02902d137b60dc0bd0f6cd1255ea99").unwrap()),
                        key_id: Uuid::new_v4()
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
