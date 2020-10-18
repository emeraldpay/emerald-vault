use crate::{sign::bip32::generate_key, storage::{error::VaultError, vault::VaultStorage}, structs::{seed::SeedSource, wallet::PKType}, to_arr, EthereumPrivateKey, EthereumAddress};
use bitcoin::{util::bip32::ExtendedPrivKey, Network, PrivateKey};
use hdpath::StandardHDPath;
use secp256k1::SecretKey;
use std::convert::TryFrom;
use crate::blockchain::addresses::{AddressFromPub, AddressCast};
use crate::sign::bitcoin::DEFAULT_SECP256K1;
use bitcoin::util::bip32::ExtendedPubKey;
use crate::blockchain::bitcoin::AddressType;
use crate::blockchain::chains::{Blockchain, BlockchainType};
use std::str::FromStr;
use emerald_hwkey::ledger::manager::LedgerKey;

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
                    let key = generate_key(&hd_path, &seed_key)?;
                    Ok(PrivateKeySource::Extended(key))
                }
            },
            SeedSource::Ledger(_) => Err(VaultError::PrivateKeyUnavailable),
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
        match self {
            SeedSource::Bytes(bytes) => match password {
                None => Err(VaultError::PasswordRequired),
                Some(password) => {
                    let seed_key = bytes.decrypt(password.as_str())?;
                    let mut result = Vec::with_capacity(hd_path_all.len());
                    for hd_path in hd_path_all {
                        let sec_key = generate_key(&hd_path, &seed_key)?;
                        let pub_key = ExtendedPubKey::from_private(&DEFAULT_SECP256K1, &sec_key);
                        let address_type = AddressType::try_from(hd_path)?;
                        let address = T::create(pub_key.public_key, &address_type, blockchain.is_mainnet())?;
                        result.push((hd_path.clone(), address));
                    }
                    Ok(result)
                }
            },
            SeedSource::Ledger(_) => {
                match blockchain.get_type() {
                    //TODO bitcoin
                    BlockchainType::Bitcoin => unimplemented!(),
                    BlockchainType::Ethereum => {
                        let mut wallet_manager = LedgerKey::new(
                            Some(StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap().to_bytes())
                        ).map_err(|_| VaultError::PrivateKeyUnavailable)?;
                        let mut result = Vec::with_capacity(hd_path_all.len());
                        for hd_path in hd_path_all {
                            let address = wallet_manager.get_address("", Some(hd_path.to_bytes()))
                                .map(|a| format!("0x{:}", a))?;
                            if let Some(address) = T::from_ethereum_address(EthereumAddress::from_str(address.as_str())?) {
                                result.push((hd_path.clone(), address));
                            }
                        }
                        Ok(result)
                    }
                }
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
    use hdpath::StandardHDPath;
    use std::str::FromStr;
    use crate::blockchain::chains::Blockchain;
    use crate::EthereumAddress;
    use bitcoin::Address;

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
}
