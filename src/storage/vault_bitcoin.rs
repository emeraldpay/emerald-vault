use std::sync::Arc;
use crate::storage::vault::VaultAccessByFile;
use crate::structs::seed::{Seed, SeedSource, SeedRef};
use crate::structs::wallet::{Wallet, WalletEntry, PKType};
use uuid::Uuid;
use crate::error::VaultError;
use hdpath::{AccountHDPath, PathValue};
use crate::blockchain::chains::{Blockchain, BlockchainType};
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, DerivationPath};
use crate::blockchain::bitcoin::{AddressType, XPub};
use crate::sign::bitcoin::DEFAULT_SECP256K1;
use crate::structs::book::AddressRef;
use emerald_hwkey::{
    ledger::{
        manager::LedgerKey,
        app_bitcoin::{
            BitcoinApp, BitcoinApps
        },
        traits::{
            LedgerApp,
            PubkeyAddressApp
        }
    },
    errors::HWKeyError
};
use crate::storage::entry::AddEntryOptions;
use crate::structs::crypto::GlobalKey;

pub struct AddBitcoinEntry {
    seeds: Arc<dyn VaultAccessByFile<Seed>>,
    wallets: Arc<dyn VaultAccessByFile<Wallet>>,
    wallet_id: Uuid,
    global: Option<GlobalKey>,
}

pub(crate) fn get_address(blockchain: &Blockchain, address_type: AddressType, account: u32, seed: Vec<u8>) -> Result<XPub, VaultError> {
    let network = blockchain.as_bitcoin_network();
    let master = ExtendedPrivKey::new_master(network.clone(), seed.as_slice())
        .map_err(|_| VaultError::InvalidPrivateKey)?;
    if !PathValue::is_ok(account) {
        return Err(VaultError::PrivateKeyUnavailable)
    }
    let account = address_type.get_hd_path(account, &network);
    let account_dp: DerivationPath = account.into();
    let xprv = master.derive_priv(&DEFAULT_SECP256K1, &account_dp)
        .map_err(|_| VaultError::PrivateKeyUnavailable)?;
    let xpub = ExtendedPubKey::from_priv(&DEFAULT_SECP256K1, &xprv);
    Ok(XPub {
        value: xpub,
        address_type,
    })
}

impl AddBitcoinEntry {
    pub fn new(wallet_id: &Uuid,
               seeds: Arc<dyn VaultAccessByFile<Seed>>,
               wallets: Arc<dyn VaultAccessByFile<Wallet>>,
               global: Option<GlobalKey>,
    ) -> AddBitcoinEntry {
        AddBitcoinEntry {
            wallet_id: wallet_id.clone(),
            seeds,
            wallets,
            global,
        }
    }

    pub fn seed_hd(
        &self,
        seed_id: Uuid,
        hd_path: AccountHDPath,
        blockchain: Blockchain,
        opts: AddEntryOptions,
    ) -> Result<usize, VaultError> {
        if blockchain.get_type() != BlockchainType::Bitcoin {
            return Err(VaultError::IncorrectBlockchainError)
        }
        let mut seed = self.seeds.get(seed_id)?;
        let address_type = AddressType::P2WPKH;
        let account = address_type.get_hd_path(hd_path.account(), &blockchain.as_bitcoin_network());
        if account.purpose() != hd_path.purpose() {
            return Err(VaultError::UnsupportedDataError("Invalid HD Path purpose for address".to_string()))
        }
        let xpub = match &seed.source {
            SeedSource::Bytes(seed) => {
                match &opts.seed_password {
                    Some(seed_password) => {
                        let seed = seed.decrypt(seed_password.as_bytes(), self.global.clone())?;
                        Some(get_address(&blockchain, address_type, account.account(), seed)?)
                    },
                    None => return Err(VaultError::PasswordRequired)
                }
            }
            SeedSource::Ledger(r) => {
                let _access_lock = r.access.lock().map_err(|_| VaultError::HWKeyFailed(HWKeyError::Unavailable))?;
                let manager = LedgerKey::new_connected();
                if let Ok(manager) = manager {
                    let bitcoin_app = manager.access::<BitcoinApp>()?;
                    let exp_app = match blockchain {
                        Blockchain::Bitcoin => Some(BitcoinApps::Mainnet),
                        Blockchain::BitcoinTestnet => Some(BitcoinApps::Testnet),
                        _ => None
                    };
                    if exp_app.is_none() || bitcoin_app.is_open() != exp_app {
                        None
                    } else {
                        let xpub = bitcoin_app.get_xpub(&account, blockchain.as_bitcoin_network())?;
                        Some(XPub::standard(xpub))
                    }
                } else {
                    None
                }
            }
        };

        if opts.xpub.is_some() && xpub.is_some() {
            // if we verified that the expected xpub and the actual xpub on ledger are the same
            // then we can remember the association between the ledger and the seed.
            if opts.xpub == xpub {
                if seed.associate() {
                    let _ = self.seeds.update(seed.clone());
                }
            } else {
                return Err(VaultError::InvalidDataError(
                    "Different xpub".to_string(),
                ));
            }
        }

        let xpub = xpub.or_else(|| {
            opts.xpub.clone()
        });

        if xpub.is_none() {
            return Err(VaultError::PublicKeyUnavailable)
        }

        let xpub = xpub.unwrap();

        if xpub.value.network != blockchain.as_bitcoin_network() {
            return Err(VaultError::IncorrectBlockchainError)
        }

        let address_ref = AddressRef::ExtendedPub(xpub);

        let mut wallet = self.wallets.get(self.wallet_id.clone())?;
        let id = wallet.next_entry_id();
        wallet.entries.push(WalletEntry {
            id,
            blockchain,
            address: Some(address_ref),
            key: PKType::SeedHd(SeedRef {
                seed_id: seed_id.clone(),
                hd_path: account.address_at(0, 0).expect("Generate first address for account"),
            }),
            ..WalletEntry::default()
        });
        wallet.entry_seq = id + 1;
        self.wallets.update(wallet.clone())?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;
    use crate::storage::vault::VaultStorage;
    use crate::mnemonic::{Mnemonic, Language};
    use crate::structs::wallet::ReservedPath;
    use std::str::FromStr;
    use crate::structs::seed::LedgerSource;

    #[test]
    fn adds_seed_entry() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let phrase = Mnemonic::try_from(
            Language::English,
            "avoid midnight couch purchase truth segment sauce claim spell spring smoke renew term stem solve",
        ).unwrap();
        let seed_id = vault.seeds().add(
            Seed {
                source: SeedSource::create_raw(phrase.seed(None)).unwrap(),
                ..Default::default()
            }
        ).unwrap();
        let wallet_id = vault.wallets().add(Wallet {
            ..Default::default()
        }).unwrap();

        let _ = vault.add_bitcoin_entry(wallet_id.clone()).seed_hd(
            seed_id,
            AccountHDPath::from_str("m/84'/0'/3'").unwrap(),
            Blockchain::Bitcoin,
            AddEntryOptions::with_seed_password(SeedSource::nokey().as_str()),
        ).expect("entry not created");

        let wallet = vault.wallets().get(wallet_id).unwrap();
        assert_eq!(
            vec![ReservedPath { seed_id, account_id: 3 }],
            wallet.reserved
        );
        assert_eq!(1, wallet.entries.len());
        let entry = &wallet.entries[0];

        assert_eq!(Blockchain::Bitcoin, entry.blockchain);
        assert!(entry.address.is_some());

        let address_ref = entry.address.as_ref().unwrap();
        match address_ref {
            AddressRef::ExtendedPub(xpub) => {
                assert_eq!(AddressType::P2WPKH, xpub.address_type);
                assert_eq!(xpub.value.to_string(), "xpub6Bmen2HSjEynDHynGWTMxhEsoAZbHfvXvQ2n43NHDvzRu7V2aKtAP2ZkbUWcvpfcEjwuzXaMJNfWhovSRzrjsmQUucpVmTKSctYcGrmrAu8")
            }
            _ => {
                panic!("not xpub")
            }
        }
    }

    #[test]
    fn adds_seed_entry_testnet() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let phrase = Mnemonic::try_from(
            Language::English,
            "quote ivory blast onion below kangaroo tonight spread awkward decide farm gun exact wood brown",
        ).unwrap();
        let seed_id = vault.seeds().add(
            Seed {
                source: SeedSource::create_raw(phrase.seed(None)).unwrap(),
                ..Default::default()
            }
        ).unwrap();
        let wallet_id = vault.wallets().add(Wallet {
            ..Default::default()
        }).unwrap();

        let _ = vault.add_bitcoin_entry(wallet_id.clone()).seed_hd(
            seed_id,
            AccountHDPath::from_str("m/84'/1'/0'").unwrap(),
            Blockchain::BitcoinTestnet,
            AddEntryOptions::with_seed_password(SeedSource::nokey().as_str()),
        ).expect("entry not created");

        let wallet = vault.wallets().get(wallet_id).unwrap();
        assert_eq!(
            vec![ReservedPath { seed_id, account_id: 0 }],
            wallet.reserved
        );
        assert_eq!(1, wallet.entries.len());
        let entry = &wallet.entries[0];

        assert_eq!(Blockchain::BitcoinTestnet, entry.blockchain);
        assert!(entry.address.is_some());

        let address_ref = entry.address.as_ref().unwrap();
        match address_ref {
            AddressRef::ExtendedPub(xpub) => {
                assert_eq!(AddressType::P2WPKH, xpub.address_type);
                assert_eq!(xpub.to_string(), "vpub5Yxb4hoHAGV32y67pPDQCbPFUbB9w95gkR1nCxv92t2axDYWeNV4xzo1wxgz8A1S5QGWusHzCP969uaBbt4hjV8CT3PKe7tfic4v9RMbFc4".to_string())
            }
            _ => {
                panic!("not xpub")
            }
        }
    }

    #[cfg(test_ledger_bitcoin)]
    #[test]
    fn add_seed_ledger() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed_id = vault.seeds().add(Seed {
            source: SeedSource::Ledger(LedgerSource { fingerprints: vec![] }),
            ..Default::default()
        }).unwrap();

        let wallet_id = vault.wallets().add(Wallet {
            ..Default::default()
        }).unwrap();

        let entry_id = vault.add_bitcoin_entry(wallet_id.clone()).seed_hd(
            seed_id,
            AccountHDPath::from_str("m/84'/0'/3'").unwrap(),
            Blockchain::Bitcoin,
            AddEntryOptions::default(),
        ).expect("entry not created");

        let wallet = vault.wallets().get(wallet_id).unwrap();
        assert_eq!(
            vec![ReservedPath { seed_id, account_id: 3 }],
            wallet.reserved
        );
        assert_eq!(1, wallet.entries.len());
        let entry = &wallet.entries[0];

        assert_eq!(Blockchain::Bitcoin, entry.blockchain);

        let address_ref = entry.address.as_ref().unwrap();
        match address_ref {
            AddressRef::ExtendedPub(xpub) => {
                assert_eq!(AddressType::P2WPKH, xpub.address_type);
                assert_eq!(xpub.to_string(), "zpub6rRF9XhDBRQSTqepDnwAPS5m3vMWTh7PGLy3DUKMKLtrmFonGeJjZGPh9zPQgp6uFz6yJ5t9b15aD6HiUMmaAds1M7pUYxsMVE5CPD6TWUL".to_string())
            }
            _ => {
                panic!("not xpub")
            }
        }
    }

    #[cfg(not(test_ledger_bitcoin))]
    #[test]
    fn add_seed_ledger_with_xpub() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed_id = vault.seeds().add(Seed {
            source: SeedSource::Ledger(LedgerSource { fingerprints: vec![], ..LedgerSource::default() }),
            ..Default::default()
        }).unwrap();

        let wallet_id = vault.wallets().add(Wallet {
            ..Default::default()
        }).unwrap();

        let _ = vault.add_bitcoin_entry(wallet_id.clone()).seed_hd(
            seed_id,
            AccountHDPath::from_str("m/84'/0'/3'").unwrap(),
            Blockchain::Bitcoin,
            AddEntryOptions {
                xpub: Some(
                    XPub::from_str(
                        "zpub6rRF9XhDBRQSTqepDnwAPS5m3vMWTh7PGLy3DUKMKLtrmFonGeJjZGPh9zPQgp6uFz6yJ5t9b15aD6HiUMmaAds1M7pUYxsMVE5CPD6TWUL"
                    ).unwrap()),
                ..AddEntryOptions::default()
            },
        ).expect("entry not created");

        let wallet = vault.wallets().get(wallet_id).unwrap();
        let entry = &wallet.entries[0];

        assert_eq!(Blockchain::Bitcoin, entry.blockchain);

        let address_ref = entry.address.as_ref().unwrap();
        match address_ref {
            AddressRef::ExtendedPub(xpub) => {
                assert_eq!(AddressType::P2WPKH, xpub.address_type);
                assert_eq!(xpub.to_string(), "zpub6rRF9XhDBRQSTqepDnwAPS5m3vMWTh7PGLy3DUKMKLtrmFonGeJjZGPh9zPQgp6uFz6yJ5t9b15aD6HiUMmaAds1M7pUYxsMVE5CPD6TWUL".to_string())
            }
            _ => {
                assert!(false, "not xpub")
            }
        }
    }

    #[test]
    fn cannot_create_with_wrong_chain_xpub() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).expect("Vault not initialized");

        let seed_id = vault.seeds().add(Seed {
            source: SeedSource::Ledger(LedgerSource { fingerprints: vec![], ..LedgerSource::default() }),
            ..Default::default()
        }).expect("No seed_id");

        let wallet_id = vault.wallets().add(Wallet {
            ..Default::default()
        }).expect("No wallet_id");

        // xpub is for mainnet, but blockchain is testnet

        let account = AccountHDPath::from_str("m/84'/0'/3'").expect("Invalid account hd");
        let xpub = XPub::from_str(
            "zpub6rRF9XhDBRQSTqepDnwAPS5m3vMWTh7PGLy3DUKMKLtrmFonGeJjZGPh9zPQgp6uFz6yJ5t9b15aD6HiUMmaAds1M7pUYxsMVE5CPD6TWUL"
        ).expect("Invalid XPub");
        let add_entry_opts = AddEntryOptions {
            xpub: Some(xpub),
            ..AddEntryOptions::default()
        };

        let added = vault
            .add_bitcoin_entry(wallet_id.clone())
            .seed_hd(
                seed_id,
                account,
                Blockchain::BitcoinTestnet,
                add_entry_opts,
            );

        assert_eq!(added.err(), Some(VaultError::IncorrectBlockchainError));
    }

    #[cfg(test_ledger_bitcoin)]
    #[test]
    fn cannot_create_with_wrong_xpub() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed_id = vault.seeds().add(Seed {
            source: SeedSource::Ledger(LedgerSource { fingerprints: vec![] }),
            ..Default::default()
        }).unwrap();

        let wallet_id = vault.wallets().add(Wallet {
            ..Default::default()
        }).unwrap();

        let added = vault.add_bitcoin_entry(wallet_id.clone()).seed_hd(
            seed_id,
            AccountHDPath::from_str("m/84'/0'/3'").unwrap(),
            Blockchain::Bitcoin,
            AddEntryOptions {
                xpub: Some(
                    XPub::from_str(
                        "zpub6qKPZBoCJ1v8JA3MqALek9x8mref4BPp77jh9FHmATRHgrj2ZEZkYTB6o4WjhUkJYxSwV5SaLqeHYRCgkQRZMNnv9pjvp3epbzJ3bDdzPZp"
                    ).unwrap()),
                ..AddEntryOptions::default()
            },
        );

        assert_eq!(added.err(), Some(VaultError::InvalidDataError("Different xpub".to_string())));
    }
}
