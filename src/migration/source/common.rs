use crate::{
    migration::source::json_data::{KeyFileV2, CryptoTypeV2},
    storage::vault::VaultStorage,
    core::chains::Blockchain,
    convert::{
        proto::{
            pk::{PrivateKeyHolder, PrivateKeyType, EthereumPk3},
            crypto::Encrypted,
            wallet::{WalletAccount, AddressType, EthereumAddress, Wallet},
            types::HasUuid
        }
    }
};
use uuid::Uuid;
use std::convert::TryFrom;

fn extract_label(kf: &KeyFileV2) -> Option<String> {
    let mut result = String::new();
    match &kf.name {
        Some(name) => result.push_str(name.as_str()),
        None => {}
    }
    match &kf.visible {
        Some(visible) if !visible => {
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str("(legacy hidden)")
        },
        _ => {}
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// Creates Private Key and Wallet with that single key
pub fn add_to_vault(blockchain: Blockchain, vault: &VaultStorage, kf: &KeyFileV2) -> Result<Uuid, String> {
    let account = match &kf.crypto {
        CryptoTypeV2::Core(data) => {
            let pk = PrivateKeyHolder {
                id: Uuid::new_v4(),
                pk: PrivateKeyType::Ethereum(
                    EthereumPk3 {
                        address: Some(kf.address),
                        key: Encrypted::try_from(data).map_err(|e| "Failed to convert encrypted Private Key")?
                    }
                )
            };
            let pk_id = pk.get_id();
            vault.keys().add(pk).map_err(|e| "Failed to add converted Private Key to the Vault")?;
            WalletAccount {
                blockchain,
                address: AddressType::Ethereum(
                    EthereumAddress {
                        address: Some(kf.address),
                        key_id: pk_id
                    }
                )
            }
        },
        CryptoTypeV2::HdWallet(_) => unimplemented!()
    };
    let wallet = Wallet {
        id: Uuid::new_v4(),
        label: extract_label(kf),
        accounts: vec![account]
    };
    let wallet_id = wallet.get_id();
    vault.wallets().add(wallet);
    Ok(wallet_id)
}
