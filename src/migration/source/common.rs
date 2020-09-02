use crate::{
    blockchain::chains::Blockchain,
    migration::source::json_data::{CryptoTypeV2, KeyFileV2},
    storage::vault::VaultStorage,
    structs::{
        crypto::Encrypted,
        pk::{EthereumPk3, PrivateKeyHolder, PrivateKeyType},
        seed::{HDPathFingerprint, LedgerSource, Seed, SeedRef, SeedSource},
        types::HasUuid,
        wallet::{PKType, Wallet, WalletEntry},
    },
};
use chrono::Utc;
use hdpath::StandardHDPath;
use std::convert::TryFrom;
use uuid::Uuid;

fn extract_label(kf: &KeyFileV2) -> Option<String> {
    let mut result = String::new();
    match &kf.name {
        Some(name) => result.push_str(name.as_str()),
        None => {}
    }
    // kf.name may be None or Some(empty) value, on both cases it makes sense to use address as a name
    if result.len() == 0 {
        match kf.address {
            Some(address) => result.push_str(address.to_string().as_str()),
            None => {}
        }
    }
    match &kf.visible {
        Some(visible) if !visible => {
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str("(legacy hidden)")
        }
        _ => {}
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// Creates Private Key and Wallet with that single key
pub fn add_to_vault(
    blockchain: Blockchain,
    vault: &VaultStorage,
    kf: &KeyFileV2,
) -> Result<Uuid, String> {
    let entry = match &kf.crypto {
        CryptoTypeV2::Core(data) => {
            let pk = PrivateKeyHolder {
                id: Uuid::new_v4(),
                pk: PrivateKeyType::EthereumPk(EthereumPk3 {
                    address: kf.address,
                    key: Encrypted::try_from(data)
                        .map_err(|_| "Failed to convert encrypted Private Key")?,
                }),
                created_at: Utc::now(),
            };
            let pk_id = pk.get_id();
            vault
                .keys()
                .add(pk)
                .map_err(|_| "Failed to add converted Private Key to the Vault")?;
            WalletEntry {
                id: 0,
                blockchain,
                address: kf.address,
                key: PKType::PrivateKeyRef(pk_id),
                ..WalletEntry::default()
            }
        }
        CryptoTypeV2::HdWallet(data) => {
            let seeds = vault.seeds();
            //during migration consider that user has only one ledger
            let existing = seeds
                .list_entries()
                .map_err(|_| "Failed to read list of current Seeds".to_string())?
                .iter()
                .find(|s| match s.source {
                    SeedSource::Ledger(_) => true,
                    _ => false,
                })
                .cloned();

            let seed_id = match &existing {
                Some(seed) => seed.id.clone(),
                None => {
                    let fingerprints = match kf.address {
                        Some(address) => {
                            let f = HDPathFingerprint::from_address(
                                StandardHDPath::try_from(data.hd_path.clone().as_str())
                                    .map_err(|_| "Unsupported HDPath")?,
                                &address,
                            );
                            vec![f]
                        }
                        None => Vec::new(),
                    };
                    let seed = Seed {
                        id: Uuid::new_v4(),
                        source: SeedSource::Ledger(LedgerSource { fingerprints }),
                        label: None,
                        created_at: Utc::now(),
                    };
                    let id = seed.id.clone();
                    seeds
                        .add(seed)
                        .map_err(|_| "Failed to add converted Ledger Seed to the Vault")?;
                    id
                }
            };

            WalletEntry {
                id: 0,
                blockchain,
                address: kf.address,
                key: PKType::SeedHd(SeedRef {
                    seed_id,
                    hd_path: StandardHDPath::try_from(data.hd_path.clone().as_str())
                        .map_err(|_| "Unsupported HDPath")?,
                }),
                ..WalletEntry::default()
            }
        }
    };

    let wallet = Wallet {
        label: extract_label(kf),
        entries: vec![entry],
        ..Wallet::default()
    };
    let wallet_id = wallet.get_id();
    vault
        .wallets()
        .add(wallet)
        .map_err(|e| format!("Failed to create wallet. {:?}", e))?;
    Ok(wallet_id)
}
