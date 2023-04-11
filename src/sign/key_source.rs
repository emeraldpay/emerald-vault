use crate::{
    sign::bip32::generate_key,
    storage::vault::VaultStorage,
    error::VaultError,
    structs::{seed::SeedSource, wallet::PKType},
    EthereumPrivateKey,
    EthereumAddress,
    blockchain::addresses::{AddressFromPub, AddressCast},
    blockchain::bitcoin::{AddressType, XPub},
    blockchain::chains::{Blockchain, BlockchainType},
    sign::bip32::generate_pubkey,
};
use bitcoin::{util::bip32::ExtendedPrivKey, Network, PrivateKey, PublicKey};
use hdpath::{StandardHDPath, AccountHDPath};
use secp256k1::SecretKey;
use std::convert::TryFrom;
use bitcoin::util::bip32::ExtendedPubKey;
use std::str::FromStr;
use emerald_hwkey::ledger::manager::LedgerKey;
use emerald_hwkey::ledger::app_ethereum::EthereumApp;
use emerald_hwkey::ledger::traits::{LedgerApp, PubkeyAddressApp};
use emerald_hwkey::ledger::app_bitcoin::{BitcoinApp, GetAddressOpts};
use emerald_hwkey::errors::HWKeyError;
use crate::structs::crypto::GlobalKey;

pub enum PrivateKeySource {
    Base(SecretKey),
    Extended(ExtendedPrivKey),
}

impl PrivateKeySource {
    pub fn into_secret(self) -> SecretKey {
        match self {
            PrivateKeySource::Base(sk) => sk,
            PrivateKeySource::Extended(ext) => ext.private_key,
        }
    }

    pub fn into_bitcoin_key(self, network: &Network) -> PrivateKey {
        match self {
            PrivateKeySource::Base(key) => PrivateKey {
                compressed: true,
                network: network.clone(),
                inner: key,
            },
            PrivateKeySource::Extended(ext) => PrivateKey::new(ext.private_key, network.clone()),
        }
    }
}

fn get_ledger_app<'a>(blockchain: BlockchainType, manager: &'a LedgerKey) -> Result<Box<dyn PubkeyAddressApp + 'a>, VaultError> {
    match blockchain {
        BlockchainType::Bitcoin => {
            let app = manager.access::<BitcoinApp>()?;
            if app.is_open().is_none() {
                Err(VaultError::PublicKeyUnavailable)
            } else {
                Ok(Box::new(app))
            }
        },
        BlockchainType::Ethereum => {
            let app = manager.access::<EthereumApp>()?;
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
        global: &Option<GlobalKey>,
        hd_path: &StandardHDPath,
    ) -> Result<PrivateKeySource, VaultError> {
        match self {
            SeedSource::Bytes(bytes) => match password {
                None => Err(VaultError::PasswordRequired),
                Some(password) => {
                    let seed_key = bytes.decrypt(password.as_bytes(), global.clone())?;
                    let key = generate_key(hd_path, &seed_key)?;
                    Ok(PrivateKeySource::Extended(key))
                }
            },
            SeedSource::Ledger(_) => Err(VaultError::PrivateKeyUnavailable),
        }
    }

    pub fn get_xpub(&self,
                    password: Option<String>,
                    global: &Option<GlobalKey>,
                    hd_path_all: &Vec<AccountHDPath>,
                    blockchain: Blockchain,
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
                    let seed_key = bytes.decrypt(password.as_bytes(), global.clone())?;
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
            SeedSource::Ledger(r) => {
                let _access_lock = r.access.lock().map_err(|_| VaultError::HWKeyFailed(HWKeyError::Unavailable))?;
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
                            global: Option<GlobalKey>,
                            hd_path_all: &Vec<StandardHDPath>,
                            blockchain: Blockchain,
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
                    let seed_key = bytes.decrypt(password.as_bytes(), global)?;
                    for hd_path in hd_path_all {
                        let pub_key = generate_pubkey(hd_path, &seed_key)?;
                        let address_type = AddressType::try_from(hd_path)?;
                        let address = T::create(PublicKey::new(pub_key.public_key), &address_type, blockchain.is_mainnet())?;
                        result.push((hd_path.clone(), address));
                    }
                    Ok(result)
                }
            },
            SeedSource::Ledger(r) => {
                let _access_lock = r.access.lock().map_err(|_| VaultError::HWKeyFailed(HWKeyError::Unavailable))?;
                let manager = LedgerKey::new_connected()
                    .map_err(|_| VaultError::PublicKeyUnavailable)?;
                match blockchain.get_type() {
                    BlockchainType::Bitcoin => {
                        let app = manager.access::<BitcoinApp>()?;
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
                        let app = manager.access::<EthereumApp>()?;
                        if app.is_open().is_none() {
                            return Err(VaultError::PrivateKeyUnavailable);
                        }
                        for hd_path in hd_path_all {
                            let address = app.get_address(hd_path, false)
                                .map(|a| a.address)?;
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
        global: Option<GlobalKey>,
    ) -> Result<PrivateKeySource, VaultError> {
        match &self {
            PKType::PrivateKeyRef(pk) => {
                let key = vault.keys().get(pk.clone())?;
                let key = match password {
                    None => return Err(VaultError::PasswordRequired),
                    Some(password) => key.decrypt(password.as_bytes(), global)?,
                };
                let key = SecretKey::from_slice(key.as_slice())
                    .map_err(|_| VaultError::InvalidPrivateKey)?;
                Ok(PrivateKeySource::Base(key))
            }
            PKType::SeedHd(seed) => {
                let seed_details = vault.seeds().get(seed.seed_id.clone())?;
                let hd_path = StandardHDPath::try_from(seed.hd_path.to_string().as_str())?;
                seed_details.source.get_pk(password, &global, &hd_path)
            }
        }
    }

    pub fn get_ethereum_pk(
        &self,
        vault: &VaultStorage,
        password: Option<String>,
        global: Option<GlobalKey>,
    ) -> Result<EthereumPrivateKey, VaultError> {
        let source = self.get_pk(vault, password, global)?;
        Ok(EthereumPrivateKey::from(source.into_secret()))
    }
}

#[cfg(test)]
mod tests {
    use crate::mnemonic::{Mnemonic, Language};
    use crate::structs::seed::{LedgerSource, SeedSource};
    use hdpath::{StandardHDPath, AccountHDPath};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use crate::blockchain::chains::Blockchain;
    use crate::EthereumAddress;
    use bitcoin::Address;
    use crate::blockchain::bitcoin::XPub;

    #[test]
    fn get_ethereum_addresses() {
        let phrase = Mnemonic::try_from(Language::English,
                                        "often impact pistol seminar park example foil urge bird balance reopen uphold enforce protect pear",
        ).unwrap();
        let seed = SeedSource::create_raw(phrase.seed(None)).unwrap();

        let addresses = seed.get_addresses::<EthereumAddress>(
            Some(SeedSource::nokey()),
            None,
            &vec![
                StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap(),
                StandardHDPath::from_str("m/44'/60'/0'/0/7").unwrap(),
                StandardHDPath::from_str("m/44'/60'/1'/0/1").unwrap(),
            ],
            Blockchain::Ethereum,
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
        let seed = SeedSource::create_raw(phrase.seed(None)).unwrap();

        let addresses = seed.get_addresses::<Address>(
            Some(SeedSource::nokey()),
            None,
            &vec![
                StandardHDPath::from_str("m/84'/0'/0'/0/0").unwrap(),
                StandardHDPath::from_str("m/84'/0'/0'/0/7").unwrap(),
                StandardHDPath::from_str("m/84'/0'/1'/0/1").unwrap(),
            ],
            Blockchain::Bitcoin,
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
        let seed = SeedSource::create_raw(phrase.seed(None)).unwrap();

        let addresses = seed.get_xpub(
            Some(SeedSource::nokey()),
            &None,
            &vec![
                AccountHDPath::from_str("m/84'/0'/0'").unwrap(),
                AccountHDPath::from_str("m/84'/0'/1'").unwrap(),
                AccountHDPath::from_str("m/44'/0'/0'").unwrap(),
            ],
            Blockchain::Bitcoin,
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
        let seed = SeedSource::create_raw(phrase.seed(None)).unwrap();

        let addresses = seed.get_xpub(
            Some(SeedSource::nokey()),
            &None,
            &vec![
                AccountHDPath::from_str("m/84'/1'/0'").unwrap(),
            ],
            Blockchain::BitcoinTestnet,
        );
        assert!(addresses.is_ok());
        let addresses = addresses.unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].0, AccountHDPath::from_str("m/84'/1'/0'").unwrap());
        assert_eq!(addresses[0].1.to_string(), "vpub5YGWRLD8AtynzsPMdPwsjXPUUqoxb6LkgByZzaJ9TS2FECgogxA3CszeC16oiz2Uc7rCcSM9U2Drmv6A9dqBS6YpSuhUEi6LmWtCkVQXc1F".to_string());
    }

    #[test]
    #[cfg(all(integration_test, speculos, feature = "hwkey-emulate"))]
    fn get_ethereum_addresses_from_speculos() {
        let seed = SeedSource::Ledger(LedgerSource {
            fingerprints: vec![],
            ..LedgerSource::default()
        });

        let addresses = seed.get_addresses::<EthereumAddress>(
            None,
            None,
            &vec![
                StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap(),
                StandardHDPath::from_str("m/44'/60'/0'/0/1").unwrap(),
                StandardHDPath::from_str("m/44'/60'/0'/0/2").unwrap(),
                StandardHDPath::from_str("m/44'/60'/0'/0/3").unwrap(),
                StandardHDPath::from_str("m/44'/60'/0'/0/4").unwrap(),
                StandardHDPath::from_str("m/44'/60'/0'/0/5").unwrap(),
                StandardHDPath::from_str("m/44'/60'/0'/0/6").unwrap(),
                StandardHDPath::from_str("m/44'/60'/0'/0/7").unwrap(),
            ],
            Blockchain::Ethereum,
        );
        println!("Addresses {:?}", &addresses);
        assert!(addresses.is_ok());
        let mut addresses = addresses.unwrap();
        assert_eq!(addresses.len(), 8);

        addresses.sort_by_key(|a| a.0.clone());

        assert_eq!(addresses[0],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap(), EthereumAddress::from_str("0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D").unwrap()));
        assert_eq!(addresses[1],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/1").unwrap(), EthereumAddress::from_str("0xd692Cb1346262F584D17B4B470954501f6715a82").unwrap()));
        assert_eq!(addresses[2],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/2").unwrap(), EthereumAddress::from_str("0xfeb0594A0561d0DF76EA8b2F52271538e6704f75").unwrap()));
        assert_eq!(addresses[3],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/3").unwrap(), EthereumAddress::from_str("0x5c886862AAbA7e342c8708190c42C14BD63e9058").unwrap()));
        assert_eq!(addresses[4],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/4").unwrap(), EthereumAddress::from_str("0x766aedBf5FC4366Fe48D49604CAE12Ba11630A60").unwrap()));
        assert_eq!(addresses[5],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/5").unwrap(), EthereumAddress::from_str("0xbC2F9a0F57d2EDD630f2327C5E0caBff565c6B13").unwrap()));
        assert_eq!(addresses[6],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/6").unwrap(), EthereumAddress::from_str("0xF0eb55adF53795257118Af626206dAb7C43F8b04").unwrap()));
        assert_eq!(addresses[7],
                   (StandardHDPath::from_str("m/44'/60'/0'/0/7").unwrap(), EthereumAddress::from_str("0x2de8e81E02154D954547322e412e3A2b2eE96C82").unwrap()));
    }

    #[test]
    #[cfg(all(integration_test, speculos, feature = "hwkey-emulate"))]
    fn get_ethereum_addresses_from_speculos_parallel() {
        let seed = SeedSource::Ledger(LedgerSource {
            fingerprints: vec![],
            ..LedgerSource::default()
        });
        let seed = Arc::new(seed);
        let hd_path = vec![
            StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap(),
            StandardHDPath::from_str("m/44'/60'/0'/0/1").unwrap(),
            StandardHDPath::from_str("m/44'/60'/0'/0/2").unwrap(),
            StandardHDPath::from_str("m/44'/60'/0'/0/3").unwrap(),
            StandardHDPath::from_str("m/44'/60'/0'/0/4").unwrap(),
            StandardHDPath::from_str("m/44'/60'/0'/0/5").unwrap(),
            StandardHDPath::from_str("m/44'/60'/0'/0/6").unwrap(),
            StandardHDPath::from_str("m/44'/60'/0'/0/7").unwrap(),
        ];
        let hd_path = Arc::new(hd_path);

        let results: Vec<Vec<(StandardHDPath, EthereumAddress)>> = vec![];
        let results_ref = Arc::new(Mutex::new(results));

        let thread_hd_path = hd_path.clone();
        let thread_seed = seed.clone();
        let thread_results = results_ref.clone();
        let t1 = thread::spawn(move || {
            let addresses = thread_seed.get_addresses::<EthereumAddress>(
                None,
                None,
                &thread_hd_path,
                Blockchain::Ethereum,
            );
            let mut addresses = addresses.unwrap();
            addresses.sort_by_key(|a| a.0.clone());
            let mut results = thread_results.lock().unwrap();
            results.push(addresses);
        });

        let thread_hd_path = hd_path.clone();
        let thread_seed = seed.clone();
        let thread_results = results_ref.clone();
        let t2 = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let addresses = thread_seed.get_addresses::<EthereumAddress>(
                None,
                None,
                &thread_hd_path,
                Blockchain::Ethereum,
            );
            let mut addresses = addresses.unwrap();
            addresses.sort_by_key(|a| a.0.clone());
            let mut results = thread_results.lock().unwrap();
            results.push(addresses);
        });

        let thread_hd_path = hd_path.clone();
        let thread_seed = seed.clone();
        let thread_results = results_ref.clone();
        let t3 = thread::spawn(move || {
            thread::sleep(Duration::from_millis(25));
            let addresses = thread_seed.get_addresses::<EthereumAddress>(
                None,
                None,
                &thread_hd_path,
                Blockchain::Ethereum,
            );
            let mut addresses = addresses.unwrap();
            addresses.sort_by_key(|a| a.0.clone());
            let mut results = thread_results.lock().unwrap();
            results.push(addresses);
        });

        t1.join().unwrap();
        t2.join().unwrap();
        t3.join().unwrap();

        let check_results = results_ref.clone();
        let mut results = check_results.lock().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], results[1]);
        assert_eq!(results[0], results[2]);
    }
}
