use crate::{
    blockchain::chains::EthereumChainId,
    convert::json::keyfile::EthereumJsonV3File,
    hdwallet::WManager,
    storage::{error::VaultError, vault::VaultStorage},
    structs::{
        seed::SeedSource,
        wallet::{EntryId, PKType, Wallet, WalletEntry},
    },
    EthereumPrivateKey,
    EthereumTransaction,
};
use hdpath::StandardHDPath;
use std::convert::{TryFrom, TryInto};
use uuid::Uuid;
use crate::sign::bip32::{generate_key};

impl WalletEntry {

    fn sign_tx_by_pk(
        &self,
        tx: EthereumTransaction,
        key: EthereumPrivateKey,
    ) -> Result<Vec<u8>, VaultError> {
        let chain_id = EthereumChainId::from(self.blockchain);
        tx.to_signed_raw(key, chain_id)
            .map_err(|_| VaultError::InvalidPrivateKey)
    }

    fn sign_tx_with_hardware(
        &self,
        tx: EthereumTransaction,
        _: Uuid, //not used yet
        hd_path: StandardHDPath,
    ) -> Result<Vec<u8>, VaultError> {
        let hd_path = StandardHDPath::try_from(hd_path.to_string().as_str())
            .map_err(|_| VaultError::InvalidDataError("HDPath".to_string()))?;

        //TODO verify actual device, right now vault just uses a first currently available device
        let mut manager = WManager::new(Some(hd_path.to_bytes()))?;
        if manager.update(None).is_err() {
            return Err(VaultError::PrivateKeyUnavailable);
        }
        if manager.devices().is_empty() {
            return Err(VaultError::PrivateKeyUnavailable);
        }
        let chain_id = EthereumChainId::from(self.blockchain);
        let rlp = tx.to_rlp(Some(chain_id.as_chainid()));
        let fd = &manager.devices()[0].1;
        let sign = manager
            .sign_transaction(&fd, &rlp, None)
            .map_err(|_| VaultError::InvalidPrivateKey)?;
        let raw = tx.raw_from_sig(Some(chain_id.as_chainid()), &sign);
        //TODO verify that signature is from the entry's address
        Ok(raw)
    }

    pub fn sign_tx(
        &self,
        tx: EthereumTransaction,
        password: Option<String>,
        vault: &VaultStorage,
    ) -> Result<Vec<u8>, VaultError> {
        if self.is_hardware(vault)? {
            return match &self.key {
                PKType::SeedHd(seed) => {
                    Ok(self.sign_tx_with_hardware(tx, seed.seed_id, seed.hd_path.clone())?)
                }
                _ => Err(VaultError::UnsupportedDataError("NOT_SEED".to_string())),
            };
        }
        // Continue with using a key stored in the vault, it's always encrypted with a password, so it's required
        if password.is_none() {
            return Err(VaultError::PasswordRequired);
        }
        let key = self.key.get_ethereum_pk(&vault, password.clone())?;
        self.sign_tx_by_pk(tx, key)
    }

    pub fn export_ethereum_pk(
        &self,
        password: String,
        vault: &VaultStorage,
    ) -> Result<EthereumPrivateKey, VaultError> {
        self.key.get_ethereum_pk(&vault, Some(password))
    }

    pub fn export_ethereum_web3(
        &self,
        password: Option<String>,
        vault: &VaultStorage,
    ) -> Result<EthereumJsonV3File, VaultError> {
        let label = self.label.clone();
        match &self.key {
            PKType::PrivateKeyRef(pk) => {
                let key = vault.keys().get(pk.clone())?;
                EthereumJsonV3File::from_wallet(label, &key)
                    .map_err(|_| VaultError::InvalidPrivateKey)
            }
            PKType::SeedHd(seed) => {
                let key = self.key.get_ethereum_pk(&vault, password.clone())?;
                EthereumJsonV3File::from_pk(label, key, password.expect("Password is not set"))
                    .map_err(|_| VaultError::InvalidPrivateKey)
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
            wallet::{PKType, WalletEntry},
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
    use crate::structs::book::AddressRef;

    #[test]
    fn sign_erc20_approve() {
        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(
                AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()
                ),
            ),
            key: PKType::PrivateKeyRef(Uuid::default()), // not used by the test
            ..WalletEntry::default()
        };
        let tx = EthereumTransaction {
            nonce: 1,
            gas_price: to_32bytes("04a817c800"),
            gas_limit: 21000,
            to: Some(EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            value: to_32bytes("0de0b6b3a7640000"),
            data: hex::decode("095ea7b300000000000000000000000036a8ce9b0b86361a02070e4303d5e24d6c63b3f10000000000000000000000000000000000000000033b2e3c9fd0803ce8000000").unwrap(),
        };
        let key = EthereumPrivateKey::from_str(
            "0x7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
        )
        .unwrap();
        let act = entry.sign_tx_by_pk(tx, key).unwrap();
        assert_eq!(
            hex::encode(act),
            "f8b1018504a817c80082520894008aeeda4d805471df9b2a5b0f38a0c3bcba786b880de0b6b3a7640000b844095ea7b300000000000000000000000036a8ce9b0b86361a02070e4303d5e24d6c63b3f10000000000000000000000000000000000000000033b2e3c9fd0803ce800000026a08675b401448f7a82e8738e35fa09fb2e2a2acaa83caaa5d81abadfa99f4d174ca063b2e9d977a4d6c4a41492b72b0d9933d835ddfdaf299fde6327389485db04c1"
        )
    }

    #[test]
    fn sign_with_provided_pk() {
        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(
                AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()
                ),
            ),
            key: PKType::PrivateKeyRef(Uuid::default()), // not used by the test
            ..WalletEntry::default()
        };
        let tx = EthereumTransaction {
            nonce: 1,
            gas_price: to_32bytes("04a817c800"),
            gas_limit: 21000,
            to: Some(
                EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
            ),
            value: to_32bytes("0de0b6b3a7640000"),
            data: vec![],
        };
        let key = EthereumPrivateKey::from_str(
            "0x7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
        )
        .unwrap();
        let act = entry.sign_tx_by_pk(tx, key).unwrap();
        assert_eq!(
            hex::encode(act),
            "f86c018504a817c80082520894008aeeda4d805471df9b2a5b0f38a0c3bcba786b880de0b6b3a76400008026a0d478c7abb05f2cf1c1c118f7f919bc11149b3b2e8b6ac78c5517d6b74aeedcb3a06f0f26ceab9e999b7357087ca1b20f214e0aea58198ace9ee76ff8abe707c9a2"
        )
    }

    #[test]
    fn sign_with_stored_pk() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let raw_pk =
            hex::decode("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let key = PrivateKeyHolder {
            id: Uuid::new_v4(),
            pk: PrivateKeyType::EthereumPk(EthereumPk3 {
                address: Some(
                    EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b")
                        .unwrap(),
                ),
                key: Encrypted::encrypt(raw_pk, "testtest").unwrap(),
            }),
            created_at: Utc::now(),
        };
        let key_id = key.get_id();
        vault.keys().add(key).expect("Key not added");

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(
                AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()
                ),
            ),
            key: PKType::PrivateKeyRef(key_id),
            ..WalletEntry::default()
        };
        let tx = EthereumTransaction {
            nonce: 1,
            gas_price: to_32bytes("04a817c800"),
            gas_limit: 21000,
            to: Some(
                EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
            ),
            value: to_32bytes("0de0b6b3a7640000"),
            data: vec![],
        };

        let act = entry
            .sign_tx(tx, Some("testtest".to_string()), &vault)
            .unwrap();
        assert_eq!(
            hex::encode(act),
            "f86c018504a817c80082520894008aeeda4d805471df9b2a5b0f38a0c3bcba786b880de0b6b3a76400008026a0d478c7abb05f2cf1c1c118f7f919bc11149b3b2e8b6ac78c5517d6b74aeedcb3a06f0f26ceab9e999b7357087ca1b20f214e0aea58198ace9ee76ff8abe707c9a2"
        )
    }

    #[test]
    fn export_stored_pk() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();
        let raw_pk =
            hex::decode("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let key = PrivateKeyHolder {
            id: Uuid::new_v4(),
            pk: PrivateKeyType::EthereumPk(EthereumPk3 {
                address: Some(
                    EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b")
                        .unwrap(),
                ),
                key: Encrypted::encrypt(raw_pk, "testtest").unwrap(),
            }),
            created_at: Utc::now(),
        };
        let key_id = vault.keys().add(key).unwrap();

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(
                AddressRef::EthereumAddress(
                    EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()
                ),
            ),
            key: PKType::PrivateKeyRef(key_id),
            ..WalletEntry::default()
        };

        let pk = entry
            .export_ethereum_pk("testtest".to_string(), &vault)
            .unwrap();
        assert_eq!(
            hex::encode(pk.0),
            "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
        )
    }

    #[test]
    fn export_pk_from_seed() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let seed = Seed {
            id: Uuid::new_v4(),
            source: SeedSource::create_bytes(
                hex::decode("0c0727514fe0c87460ddc2bff08075174e1b45283db9d6d34ae23fb877dd12da98d6235f56d9cc4ce3ec245ffe226176338569c59db502ccebfb5c6cd6a264b4").unwrap(),
                "test1234",
            ).unwrap(),
            label: None,
            created_at: Utc::now(),
        };
        let seed_id = vault.seeds().add(seed).unwrap();

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: None, //0xC27fBF02FB577683593b1114180CA6E2c88510A0
            key: PKType::SeedHd(SeedRef {
                seed_id,
                hd_path: StandardHDPath::try_from("m/44'/60'/2'/0/52").unwrap(),
            }),
            ..WalletEntry::default()
        };

        let pk = entry
            .export_ethereum_pk("test1234".to_string(), &vault)
            .unwrap();
        assert_eq!(
            hex::encode(pk.0),
            "62a54ec79949cf6eb3bec6d67a3cd5fab835899f80c99785b73e8cd2ae9cfadb"
        )
    }

    #[test]
    fn sign_tx_with_ledger() {
        if !is_ledger_enabled() {
            warn!("Ledger test is disabled");
            return;
        }

        let test_txes = read_test_txes();
        let exp = &test_txes[0];

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

        let tx = EthereumTransaction {
            nonce: 0,
            gas_price: to_32bytes("04e3b29200"),
            gas_limit: 21000,
            to: Some(
                EthereumAddress::from_str("0x78296F1058dD49C5D6500855F59094F0a2876397").unwrap(),
            ),
            value: to_32bytes("0de0b6b3a7640000"),
            data: vec![],
        };

        let signed = entry.sign_tx(tx, None, &vault).unwrap();
        let signed = hex::encode(signed);
        assert!(signed.starts_with(
            "f86d80\
             85\
             04e3b29200\
             82\
             5208\
             94\
             78296f1058dd49c5d6500855f59094f0a2876397\
             88\
             0de0b6b3a7640000\
             80\
             81\
             9d\
             a0"
        ));

        assert_eq!(exp.raw, signed);
    }
}
