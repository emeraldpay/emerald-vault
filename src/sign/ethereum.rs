use crate::{convert::json::keyfile::EthereumJsonV3File, storage::vault::VaultStorage, error::VaultError, structs::{
    wallet::{PKType, WalletEntry},
    seed::{SeedSource}
}, EthereumPrivateKey, EthereumAddress};
use hdpath::StandardHDPath;
use std::convert::TryFrom;
use std::str::FromStr;
use uuid::Uuid;
use emerald_hwkey::ledger::connect::LedgerKeyShared;
use emerald_hwkey::ledger::app::EthereumApp;
use emerald_hwkey::ledger::app::LedgerApp;
use emerald_hwkey::errors::HWKeyError;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rand::rngs::OsRng;
use emerald_hwkey::ledger::connect::LedgerKey;
use crate::ethereum::signature::{EthereumBasicSignature, Signable, SignableHash};
use crate::ethereum::transaction::EthereumTransaction;

impl WalletEntry {
    fn sign_tx_by_pk<TX>(
        &self,
        tx: TX,
        key: EthereumPrivateKey,
    ) -> Result<Vec<u8>, VaultError> where TX: EthereumTransaction {
        tx.sign(key)
            .map_err(|_| VaultError::InvalidPrivateKey)
    }

    fn sign_tx_with_hardware<TX>(
        &self,
        tx: TX,
        _: Uuid, //not used yet
        hd_path: StandardHDPath,
    ) -> Result<Vec<u8>, VaultError> where TX: EthereumTransaction + Signable {
        let hd_path = StandardHDPath::try_from(hd_path.to_string().as_str())
            .map_err(|_| VaultError::InvalidDataError("HDPath".to_string()))?;

        //TODO verify actual device, right now vault just uses a first currently available device
        let manager = LedgerKeyShared::instance().map_err(|_| VaultError::PrivateKeyUnavailable)?;
        let ethereum_app = manager.access::<EthereumApp>()?;
        if ethereum_app.is_open().is_none() {
            return Err(VaultError::PrivateKeyUnavailable);
        }
        let expected_from = ethereum_app.get_address(&hd_path, false).ok()
            .map(|ar| ar.address)
            .and_then(|addr| EthereumAddress::from_str(addr.as_str()).ok());

        if expected_from.is_none() {
            return Err(VaultError::PublicKeyUnavailable);
        }
        let expected_from = expected_from.unwrap();

        let rlp = tx.encode_unsigned();
        let sign = ethereum_app
            .sign_transaction(&rlp, &hd_path)
            .map_err(VaultError::HWKeyFailed)?;
        let sign = EthereumBasicSignature::from(sign);
        let raw = tx.encode_signed(&sign);

        let verified = sign.recover_eip155(tx.get_chain()).verify(&tx, &expected_from)?;
        if !verified {
            return Err(VaultError::InvalidPrivateKey);
        }
        Ok(raw)
    }

    pub fn sign_tx<TX: EthereumTransaction + Signable>(
        &self,
        tx: TX,
        password: Option<String>,
        vault: &VaultStorage,
    ) -> Result<Vec<u8>, VaultError> {

        if let Some(mut seed) = self.get_seed(vault)? {
            if let SeedSource::Ledger(ledger) = seed.clone().source {
                let _access_lock = ledger.access.lock().map_err(|_| VaultError::HWKeyFailed(HWKeyError::Unavailable))?;
                let hd_path = self.entry_hd().expect("No HDPath for Seed entry");
                let tx = self.sign_tx_with_hardware(tx, seed.id, hd_path);
                if tx.is_ok() {
                    // when signing we made sure that the expected address belongs to the current ledger
                    if seed.associate() {
                        let _ = vault.seeds().update(seed.clone());
                    }
                }
                return tx
            }
        }

        // Continue with using a key stored in the vault, it's always encrypted with a password, so it's required
        if password.is_none() {
            return Err(VaultError::PasswordRequired);
        }
        let key = self.key.get_ethereum_pk(&vault, password.clone(), vault.global_key().get_if_exists()?)?;
        self.sign_tx_by_pk::<TX>(tx, key)
    }

    pub fn export_ethereum_pk(
        &self,
        password: String,
        vault: &VaultStorage,
    ) -> Result<EthereumPrivateKey, VaultError> {
        self.key.get_ethereum_pk(&vault, Some(password), vault.global_key().get_if_exists()?)
    }

    pub fn export_ethereum_web3(
        &self,
        password: &str,
        vault: &VaultStorage,
    ) -> Result<(String, EthereumJsonV3File), VaultError> {
        let label = self.label.clone();
        let key = match &self.key {
            PKType::PrivateKeyRef(pk) => {
                let raw_pk = vault.keys().get(pk.clone())?.decrypt(password.as_bytes(), vault.global_key().get_if_exists()?)?;
                EthereumPrivateKey::try_from(raw_pk.as_slice())?
            }
            PKType::SeedHd(_) => {
                self.key.get_ethereum_pk(&vault, Some(password.to_string()), vault.global_key().get_if_exists()?)?
            }
        };

        // generate a new temp password for the exported PK
        // should never reuse the original password as it may be global or used by other wallets
        let mut rnd = OsRng::default();
        let password: String = std::iter::repeat(())
            .take(20)
            .map(|_| rnd.sample(Alphanumeric))
            .map(char::from)
            .collect();

        let pk = EthereumJsonV3File::from_pk(label, key, password.to_string())
            .map_err(|_| VaultError::InvalidPrivateKey)?;
        Ok((password, pk))
    }
}

impl WalletEntry {

    pub fn sign_message(&self,
                         msg: &dyn SignableHash,
                         password: Option<String>,
                         vault: &VaultStorage) -> Result<String, VaultError> {
        if self.is_hardware(vault)? {
            //TODO
            return Err(VaultError::UnsupportedDataError("Hardware Signing is not available".to_string()));
        }
        // Continue with using a key stored in the vault, it's always encrypted with a password, so it's required
        if password.is_none() {
            return Err(VaultError::PasswordRequired);
        }
        let key = self.key.get_ethereum_pk(&vault, password.clone(), vault.global_key().get_if_exists()?)?;


        let signature = key.sign::<EthereumBasicSignature>(msg)?;
        Ok(signature.to_string())
    }

}

#[cfg(test)]
mod tests {
    use crate::{
        blockchain::chains::Blockchain,
        storage::vault::VaultStorage,
        structs::{
            book::AddressRef,
            crypto::Encrypted,
            pk::{EthereumPk3, PrivateKeyHolder, PrivateKeyType},
            seed::{LedgerSource, Seed, SeedRef, SeedSource},
            types::HasUuid,
            wallet::{PKType, WalletEntry, Wallet},
        },
        EthereumAddress,
        EthereumPrivateKey,
        EthereumLegacyTransaction,
    };
    use chrono::Utc;
    use hdpath::StandardHDPath;
    use std::{convert::TryFrom, str::FromStr};
    use num::Num;
    use num_bigint::BigUint;
    use tempdir::TempDir;
    use uuid::Uuid;
    use crate::chains::EthereumChainId;
    use crate::mnemonic::{Language, Mnemonic};
    use crate::tests::{read_test_txes};

    #[test]
    fn sign_erc20_approve() {
        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
            )),
            key: PKType::PrivateKeyRef(Uuid::default()), // not used by the test
            ..WalletEntry::default()
        };
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 1,
            gas_price: BigUint::from_str_radix("04a817c800", 16).unwrap(),
            gas_limit: 21000,
            to: Some(EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap()),
            value: BigUint::from_str_radix("0de0b6b3a7640000", 16).unwrap(),
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
    fn sign_weth_deposit() {
        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
            )),
            key: PKType::PrivateKeyRef(Uuid::default()), // not used by the test
            ..WalletEntry::default()
        };
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 1,
            gas_price: BigUint::from_str_radix("04a817c800", 16).unwrap(),
            gas_limit: 50000,
            to: Some(EthereumAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap()),
            value: BigUint::from_str_radix("0de0b6b3a7640000", 16).unwrap(),
            data: hex::decode("d0e30db0").unwrap(),
        };
        let key = EthereumPrivateKey::from_str(
            "0x7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
        )
            .unwrap();
        let act = entry.sign_tx_by_pk(tx, key).unwrap();
        assert_eq!(
            hex::encode(act),
            "f870018504a817c80082c35094c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2880de0b6b3a764000084d0e30db025a00f1e12799f687fcf135730cff44f3fd34d3bd86e794d059c8fdffb29c8aca37da0190f13cfca41d88cdfc7c730adfc50f73d23c13a246c4bd31114312e5e9c8c3a"
        )
    }

    #[test]
    fn sign_with_provided_pk() {
        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
            )),
            key: PKType::PrivateKeyRef(Uuid::default()), // not used by the test
            ..WalletEntry::default()
        };
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 1,
            gas_price: BigUint::from_str_radix("04a817c800", 16).unwrap(),
            gas_limit: 21000,
            to: Some(
                EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
            ),
            value: BigUint::from_str_radix("0de0b6b3a7640000", 16).unwrap(),
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
                key: Encrypted::encrypt(raw_pk, "testtest".as_bytes(), None).unwrap(),
            }),
            created_at: Utc::now(),
        };
        let key_id = key.get_id();
        vault.keys().add(key).expect("Key not added");

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
            )),
            key: PKType::PrivateKeyRef(key_id),
            ..WalletEntry::default()
        };
        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 1,
            gas_price: BigUint::from_str_radix("04a817c800", 16).unwrap(),
            gas_limit: 21000,
            to: Some(
                EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
            ),
            value: BigUint::from_str_radix("0de0b6b3a7640000", 16).unwrap(),
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
                key: Encrypted::encrypt(raw_pk, "testtest".as_bytes(), None).unwrap(),
            }),
            created_at: Utc::now(),
        };
        let key_id = vault.keys().add(key).unwrap();

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b").unwrap(),
            )),
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
            source: SeedSource::create_raw(
                hex::decode("0c0727514fe0c87460ddc2bff08075174e1b45283db9d6d34ae23fb877dd12da98d6235f56d9cc4ce3ec245ffe226176338569c59db502ccebfb5c6cd6a264b4").unwrap(),
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
            .export_ethereum_pk(SeedSource::nokey(), &vault)
            .unwrap();
        assert_eq!(
            hex::encode(pk.0),
            "62a54ec79949cf6eb3bec6d67a3cd5fab835899f80c99785b73e8cd2ae9cfadb"
        )
    }

    #[test]
    #[cfg(all(integration_test, ledger))]
    fn sign_tx_with_ledger() {
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

        let tx = EthereumLegacyTransaction {
            chain_id: EthereumChainId::Ethereum,
            nonce: 0,
            gas_price: BigUint::from_str_radix("04e3b29200", 16).unwrap(),
            gas_limit: 21000,
            to: Some(
                EthereumAddress::from_str("0x78296F1058dD49C5D6500855F59094F0a2876397").unwrap(),
            ),
            value: BigUint::from_str_radix("0de0b6b3a7640000", 16).unwrap(),
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

    #[test]
    fn sign_erc191_message() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let global_store = vault.global_key();
        global_store.create("test-1").unwrap();
        let global = Some(global_store.get().unwrap());

        let phrase = Mnemonic::try_from(Language::English,
                                        "often impact pistol seminar park example foil urge bird balance reopen uphold enforce protect pear",
        ).unwrap();

        let seed = Seed {
            id: Uuid::new_v4(),
            source: SeedSource::create_raw(phrase.seed(None)).unwrap()
                .reencrypt(SeedSource::nokey().as_bytes(), "test-1".as_bytes(), global.unwrap()).unwrap(),
            label: None,
            created_at: Utc::now(),
        };
        let seed_id = vault.seeds().add(seed).unwrap();

        let entry = WalletEntry {
            id: 0,
            blockchain: Blockchain::Ethereum,
            address: Some(AddressRef::EthereumAddress(
                EthereumAddress::from_str("0x23B851d476a3E523d52269746C95bD13bAB81690").unwrap(),
            )),
            key: PKType::SeedHd(SeedRef { seed_id, hd_path: StandardHDPath::from_str("m/44'/60'/0'/0/2").unwrap()}),
            ..WalletEntry::default()
        };

        vault.wallets()
            .add(Wallet {
                entries: vec![],
                ..Wallet::default()
            }).expect("wallet not created");


        let signed = entry.sign_message(
            &"test test test".to_string(), Some("test-1".to_string()), &vault
        );

        assert!(signed.is_ok());
        let signed = signed.unwrap();
        assert_eq!(signed, "0xc7be6a5bf16f3e8af73ef954e17a7988346201f1b5563aaff66e2fd16d0cb13268cd7ac4095da896a78b002f693086287fc7894f99661c69972b6cbf402ca72a1c".to_string());
    }
}
