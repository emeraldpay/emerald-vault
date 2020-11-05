use crate::{sign::bip32::generate_key, storage::{error::VaultError, vault::VaultStorage}, structs::{seed::SeedSource, wallet::PKType}, to_arr, EthereumPrivateKey, EthereumAddress};
use bitcoin::{util::bip32::ExtendedPrivKey, Network, PrivateKey};
use hdpath::{StandardHDPath, AccountHDPath};
use secp256k1::SecretKey;
use std::convert::TryFrom;
use crate::blockchain::addresses::{AddressFromPub, AddressCast};
use crate::sign::bitcoin::DEFAULT_SECP256K1;
use bitcoin::util::bip32::ExtendedPubKey;
use crate::blockchain::bitcoin::{AddressType, XPub};
use crate::blockchain::chains::{Blockchain, BlockchainType};
use std::str::FromStr;
use emerald_hwkey::ledger::manager::LedgerKey;
use emerald_hwkey::ledger::app_ethereum::EthereumApp;
use emerald_hwkey::ledger::traits::{LedgerApp, PubkeyAddressApp};
use emerald_hwkey::ledger::app_bitcoin::{BitcoinApp, GetAddressOpts};
use crate::sign::bip32::generate_pubkey;

pub enum PrivateKeySource {
    Base(SecretKey),
    Extended(ExtendedPrivKey),
}

impl PrivateKeySource {
    pub fn into_secret(self) -> SecretKey {
        match self {
            PrivateKeySource::Base(sk) => sk,
            PrivateKeySource::Extended(ext) => ext.private_key.key,
        }
    }

    pub fn into_bitcoin_key(self, network: &Network) -> PrivateKey {
        match self {
            PrivateKeySource::Base(key) => PrivateKey {
                compressed: true,
                network: network.clone(),
                key,
            },
            PrivateKeySource::Extended(ext) => ext.private_key,
        }
    }
}

fn get_ledger_app<'a>(blockchain: BlockchainType, manager: &'a LedgerKey) -> Result<Box<dyn PubkeyAddressApp + 'a>, VaultError> {
    match blockchain {
        BlockchainType::Bitcoin => {
            let app = BitcoinApp::new(manager);
            if app.is_open().is_none() {
                Err(VaultError::PublicKeyUnavailable)
            } else {
                Ok(Box::new(app))
            }
        },
        BlockchainType::Ethereum => {
            let app = EthereumApp::new(manager);
            if app.is_open().is_none() {
                Err(VaultError::PublicKeyUnavailable)
            } else {
                Ok(Box::new(app))
            }
        }
    }
}

impl SeedSource {
    pub fn get_pk(
        &self,
        password: Option<String>,
        hd_path: &StandardHDPath,
    ) -> Result<PrivateKeySource, VaultError> {
        match self {
            SeedSource::Bytes(bytes) => match password {
                None => Err(VaultError::PasswordRequired),
                Some(password) => {
                    let seed_key = bytes.decrypt(password.as_str())?;
                    let key = generate_key(hd_path, &seed_key)?;
                    Ok(PrivateKeySource::Extended(key))
                }
            },
            SeedSource::Ledger(_) => Err(VaultError::PrivateKeyUnavailable),
        }
    }

    pub fn get_xpub(&self,
                    password: Option<String>,
                    hd_path_all: &Vec<AccountHDPath>,
                    blockchain: Blockchain
    ) -> Result<Vec<(AccountHDPath, XPub)>, VaultError> {
        if hd_path_all.is_empty() {
            return Ok(vec![])
        }
        let mut result = Vec::with_capacity(hd_path_all.len());
        let network = match blockchain.get_type() {
            BlockchainType::Bitcoin => blockchain.as_bitcoin_network(),
            // ethereum uses bitcoin network code
            BlockchainType::Ethereum => Blockchain::Bitcoin.as_bitcoin_network()
        };

        match self {
            SeedSource::Bytes(bytes) => match password {
                None => Err(VaultError::PasswordRequired),
                Some(password) => {
                    let seed_key = bytes.decrypt(password.as_str())?;
                    for hd_path in hd_path_all {
                        let pub_key = ExtendedPubKey {
                            network,
                            ..generate_pubkey(hd_path, &seed_key)?
                        };
                        let address_type = AddressType::try_from(hd_path)?;
                        result.push((hd_path.clone(), XPub { value: pub_key, address_type}));
                    }
                    Ok(result)
                }
            }
            SeedSource::Ledger(_) => {
                let manager = LedgerKey::new_connected()
                    .map_err(|_| VaultError::PublicKeyUnavailable)?;
                let app = get_ledger_app(blockchain.get_type(), &manager)?;
                for hd_path in hd_path_all {
                    let xpub = app.get_xpub(hd_path, network)?;
                    let address_type = AddressType::try_from(hd_path)?;
                    result.push((hd_path.clone(), XPub { value: xpub, address_type}));
                }
                Ok(result)
            }
        }
    }

    pub fn get_addresses<T>(&self,
                          password: Option<String>,
                          hd_path_all: &Vec<StandardHDPath>,
                          blockchain: Blockchain
    ) -> Result<Vec<(StandardHDPath, T)>, VaultError>
        where T: AddressFromPub<T> + AddressCast<T> {
        if hd_path_all.is_empty() {
            return Ok(vec![])
        }
        let mut result = Vec::with_capacity(hd_path_all.len());
        match self {
            SeedSource::Bytes(bytes) => match password {
                None => Err(VaultError::PasswordRequired),
                Some(password) => {
                    let seed_key = bytes.decrypt(password.as_str())?;
                    for hd_path in hd_path_all {
                        let pub_key = generate_pubkey(hd_path, &seed_key)?;
                        let address_type = AddressType::try_from(hd_path)?;
                        let address = T::create(pub_key.public_key, &address_type, blockchain.is_mainnet())?;
                        result.push((hd_path.clone(), address));
                    }
                    Ok(result)
                }
            },
            SeedSource::Ledger(_) => {
                let manager = LedgerKey::new_connected()
                    .map_err(|_| VaultError::PublicKeyUnavailable)?;
                match blockchain.get_type() {
                    BlockchainType::Bitcoin => {
                        let app = BitcoinApp::new(&manager);
                        if app.is_open().is_none() {
                            return Err(VaultError::PublicKeyUnavailable);
                        }
                        let opts = GetAddressOpts {
                            network: blockchain.as_bitcoin_network(),
                            ..Default::default()
                        };
                        for hd_path in hd_path_all {
                            let address = app.get_address(hd_path, opts)?;
                            if let Some(address) = T::from_bitcoin_address(address.address) {
                                result.push((hd_path.clone(), address));
                            }
                        }
                    },
                    BlockchainType::Ethereum => {
                        let app = EthereumApp::new(&manager);
                        if app.is_open().is_none() {
                            return Err(VaultError::PrivateKeyUnavailable);
                        }
                        for hd_path in hd_path_all {
                            let address = app.get_address(hd_path, false)
                                .map(|a| format!("0x{:}", a.address))?;
                            if let Some(address) = T::from_ethereum_address(EthereumAddress::from_str(address.as_str())?) {
                                result.push((hd_path.clone(), address));
                            }
                        }
                    }
                }
                Ok(result)
            },
        }
    }
}

impl PKType {
    pub fn get_pk(
        &self,
        vault: &VaultStorage,
        password: Option<String>,
    ) -> Result<PrivateKeySource, VaultError> {
        match &self {
            PKType::PrivateKeyRef(pk) => {
                let key = vault.keys().get(pk.clone())?;
                let key = match password {
                    None => return Err(VaultError::PasswordRequired),
                    Some(password) => key.decrypt(password.as_str())?,
                };
                let key = SecretKey::from_slice(key.as_slice())
                    .map_err(|e| VaultError::InvalidPrivateKey)?;
                Ok(PrivateKeySource::Base(key))
            }
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(seed.seed_id.clone())?;
                let hd_path = StandardHDPath::try_from(seed.hd_path.to_string().as_str())?;
                seed_details.source.get_pk(password, &hd_path)
            }
        }
    }

    pub fn get_ethereum_pk(
        &self,
        vault: &VaultStorage,
        password: Option<String>,
    ) -> Result<EthereumPrivateKey, VaultError> {
        let source = self.get_pk(vault, password)?;
        Ok(EthereumPrivateKey::from(source.into_secret()))
    }
}

#[cfg(test)]
mod tests {
    use crate::mnemonic::{Mnemonic, Language};
    use crate::structs::seed::SeedSource;
    use hdpath::{StandardHDPath, AccountHDPath};
    use std::str::FromStr;
    use crate::blockchain::chains::Blockchain;
    use crate::EthereumAddress;
    use bitcoin::Address;
    use crate::blockchain::bitcoin::XPub;

    #[test]
    fn get_ethereum_addresses() {
        let phrase = Mnemonic::try_from(Language::English,
                                        "often impact pistol seminar park example foil urge bird balance reopen uphold enforce protect pear",
        ).unwrap();
        let seed = SeedSource::create_bytes(phrase.seed(None), "test").unwrap();

        let addresses = seed.get_addresses::<EthereumAddress>(
            Some("test".to_string()),
            &vec![
                StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap(),
                StandardHDPath::from_str("m/44'/60'/0'/0/7").unwrap(),
                StandardHDPath::from_str("m/44'/60'/1'/0/1").unwrap(),
            ],
            Blockchain::Ethereum
        );
        assert!(addresses.is_ok());
        let addresses = addresses.unwrap();
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap(), EthereumAddress::from_str("0x54b6785921762808D36DB528bB1d446A91633205").unwrap()));
        assert_eq!(addresses[1],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/7").unwrap(), EthereumAddress::from_str("0x677009BB7C387fA265c1697772e6FA3772548e87").unwrap()));
        assert_eq!(addresses[2],
                   (StandardHDPath::from_str("m/44'/60'/1'/0/1").unwrap(), EthereumAddress::from_str("0x77c9eF54AF7c2cf2804EEcaB670653F0dBe3896f").unwrap()));
    }

    #[test]
    fn get_bitcoin_addresses() {
        let phrase = Mnemonic::try_from(Language::English,
                                        "often impact pistol seminar park example foil urge bird balance reopen uphold enforce protect pear",
        ).unwrap();
        let seed = SeedSource::create_bytes(phrase.seed(None), "test").unwrap();

        let addresses = seed.get_addresses::<Address>(
            Some("test".to_string()),
            &vec![
                StandardHDPath::from_str("m/84'/0'/0'/0/0").unwrap(),
                StandardHDPath::from_str("m/84'/0'/0'/0/7").unwrap(),
                StandardHDPath::from_str("m/84'/0'/1'/0/1").unwrap(),
            ],
            Blockchain::Bitcoin
        );
        assert!(addresses.is_ok());
        let addresses = addresses.unwrap();
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0],
                   (StandardHDPath::from_str("m/84'/0'/0'/0/0").unwrap(), Address::from_str("bc1qtjdjzmu30f32u8swgu3r7tf9u03t72r8pevmaw").unwrap()));
        assert_eq!(addresses[1],
                   (StandardHDPath::from_str("m/84'/0'/0'/0/7").unwrap(), Address::from_str("bc1qx58fuq5dsa6yxeyzsz4djfdmn8xdkva3lfp0yc").unwrap()));
        assert_eq!(addresses[2],
                   (StandardHDPath::from_str("m/84'/0'/1'/0/1").unwrap(), Address::from_str("bc1q8yac70syq400tclzf9mx9r7682uudkddd9zpqw").unwrap()));
    }

    #[test]
    fn get_bitcoin_xpub() {
        let phrase = Mnemonic::try_from(Language::English,
                                        "often impact pistol seminar park example foil urge bird balance reopen uphold enforce protect pear",
        ).unwrap();
        let seed = SeedSource::create_bytes(phrase.seed(None), "test").unwrap();

        let addresses = seed.get_xpub(
            Some("test".to_string()),
            &vec![
                AccountHDPath::from_str("m/84'/0'/0'").unwrap(),
                AccountHDPath::from_str("m/84'/0'/1'").unwrap(),
                AccountHDPath::from_str("m/44'/0'/0'").unwrap(),
            ],
            Blockchain::Bitcoin
        );
        assert!(addresses.is_ok());
        let addresses = addresses.unwrap();
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0],
                   (AccountHDPath::from_str("m/84'/0'/0'").unwrap(),
                    XPub::from_str("zpub6qiGchfLTBKAUuXxeAYcvS6b8pUbyC6gNtdPk4X2PHQpyGK65jWfsuEHPvSAjGzpqVdCTaSD3ZbskhNX8yrbRhZeKsQXH1n9ognMftpUkdm").unwrap())
        );
        assert_eq!(addresses[1],
                   (AccountHDPath::from_str("m/84'/0'/1'").unwrap(),
                    XPub::from_str("zpub6qiGchfLTBKAZGwrEPTstgvCABFqbcatXwVk9yVGL7hQa8LpLUpmUp5LCYQ8PuFfLqDXmAbqHJnTUAXUCVyxMoiUdpTe7UopegvNRaXer5F").unwrap())
        );
        assert_eq!(addresses[2],
                   (AccountHDPath::from_str("m/44'/0'/0'").unwrap(),
                    XPub::from_str("xpub6CmJhyou3wpaQ5CuN4xC31XRrGReSzdzr4ySLwox2xAF7CnJzPJs97pTkewViGCRZHcjAfEKLoZvnuoLTv5y8y8CMWoZLUbjzJwTqGCBa5v").unwrap())
        );
    }

    #[test]
    fn get_bitcoin_testnet_xpub() {
        let phrase = Mnemonic::try_from(Language::English,
                                        "often impact pistol seminar park example foil urge bird balance reopen uphold enforce protect pear",
        ).unwrap();
        let seed = SeedSource::create_bytes(phrase.seed(None), "test").unwrap();

        let addresses = seed.get_xpub(
            Some("test".to_string()),
            &vec![
                AccountHDPath::from_str("m/84'/1'/0'").unwrap(),
            ],
            Blockchain::BitcoinTestnet
        );
        assert!(addresses.is_ok());
        let addresses = addresses.unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].0, AccountHDPath::from_str("m/84'/1'/0'").unwrap());
        assert_eq!(addresses[0].1.to_string(), "vpub5YGWRLD8AtynzsPMdPwsjXPUUqoxb6LkgByZzaJ9TS2FECgogxA3CszeC16oiz2Uc7rCcSM9U2Drmv6A9dqBS6YpSuhUEi6LmWtCkVQXc1F".to_string());
    }
}
