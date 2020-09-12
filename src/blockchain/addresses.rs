use crate::blockchain::bitcoin::{XPub, AddressType};
use crate::storage::error::VaultError;
use bitcoin::{Address as BitcoinAddress, PublicKey, Network};
use crate::blockchain::ethereum::EthereumAddress;
use crate::sign::bitcoin::DEFAULT_SECP256K1;
use bitcoin::util::bip32::ChildNumber;

pub trait AddressFromPub<T> {
    fn create(pubkey: PublicKey, address_type: &AddressType, mainnet: bool) -> Result<T, ()>;
}

pub trait AddressCast<T> {
    fn from_ethereum_address(x: EthereumAddress) -> Option<T>;
    fn from_bitcoin_address(x: BitcoinAddress) -> Option<T>;
}

impl AddressFromPub<BitcoinAddress> for BitcoinAddress {
    fn create(pubkey: PublicKey, address_type: &AddressType, mainnet: bool) -> Result<BitcoinAddress, ()> {
        let network = if mainnet {
            Network::Bitcoin
        } else {
            Network::Testnet
        };
        let address = match address_type {
            AddressType::P2WPKH => BitcoinAddress::p2wpkh(&pubkey, network).map_err(|_| ())?,
            _ => return Err(())
        };
        Ok(address)
    }
}

impl AddressCast<BitcoinAddress> for BitcoinAddress {
    fn from_ethereum_address(x: EthereumAddress) -> Option<BitcoinAddress> {
        None
    }

    fn from_bitcoin_address(x: BitcoinAddress) -> Option<BitcoinAddress> {
        Some(x)
    }
}

impl AddressFromPub<EthereumAddress> for EthereumAddress {
    fn create(pubkey: PublicKey, _: &AddressType, _: bool) -> Result<EthereumAddress, ()> {
        Ok(EthereumAddress::from(pubkey.key))
    }
}

impl AddressCast<EthereumAddress> for EthereumAddress {
    fn from_ethereum_address(x: EthereumAddress) -> Option<EthereumAddress> {
        Some(x)
    }

    fn from_bitcoin_address(x: BitcoinAddress) -> Option<EthereumAddress> {
        None
    }
}

impl XPub {
    pub fn get_address<T>(&self, index: u32) -> Result<T, VaultError>
        where T: AddressFromPub<T> {
        let child = ChildNumber::from_normal_idx(index)
            .map_err(|_| VaultError::PublicKeyUnavailable)?;
        let pk = self.value.ckd_pub(&DEFAULT_SECP256K1, child)
            .map_err(|_| VaultError::PublicKeyUnavailable)?;
        T::create(pk.public_key, &self.address_type, self.value.network == Network::Bitcoin)
            .map_err(|_| VaultError::PublicKeyUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::bitcoin::XPub;
    use std::str::FromStr;
    use bitcoin::Address;
    use crate::EthereumAddress;

    // test seed: anchor badge zone antique book leader cupboard wolf confirm average unable nut tortoise dinner private

    #[test]
    fn gets_bitcoin_address() {
        //m/84'/0'/0'/0/0
        let xpub = XPub::from_str("zpub6sZND4YD5Xui5KDmcXf7sLccderNJ5fJvNXHrrUuTuoSPbccHgJmk8sDzSi1k2nTRG31VuVe6Ydf7BWHj1TxPPKQk8bGqN2S7uMqDxNL7LS").unwrap();

        assert_eq!(
            Address::from_str("bc1q8redwn9d9qr0nkp7ah367u56ufxjprf0lvp7an").unwrap(),
            xpub.get_address(0).unwrap()
        );
        assert_eq!(
            Address::from_str("bc1q8lv69l5lnnpals79jqn78a3fy2eh8t9uls828y").unwrap(),
            xpub.get_address(1).unwrap()
        );
        assert_eq!(
            Address::from_str("bc1qetmge23y3ns900ktwruhqrqwdrp5983lt4wsw0").unwrap(),
            xpub.get_address(10).unwrap()
        );
        assert_eq!(
            Address::from_str("bc1q5gumd2vpylwt5swlmsuqewjr4vx2rwvqhf2jea").unwrap(),
            xpub.get_address(101).unwrap()
        );
    }

    #[test]
    fn gets_ethereum_address() {
        //m/44'/60'/0'/0/0
        let xpub = XPub::from_str("xpub6De1x1CWVhoDaiJo4AVczmWfjXZq29HhT4P3buhWTztZKXb2HZipE25x7ZjoPS2viEfmtrzpF57YajKfc8AZANBS4zk142eyjrSExwSifYw").unwrap();

        assert_eq!(
            EthereumAddress::from_str("0x7Bd9D156C6624b4D9a429cf81b91a9B500bDE2C7").unwrap(),
            xpub.get_address(0).unwrap()
        );
        assert_eq!(
            EthereumAddress::from_str("0x433aa99be71189F76e57541AFd5d6d4c5829d976").unwrap(),
            xpub.get_address(1).unwrap()
        );
        assert_eq!(
            EthereumAddress::from_str("0x4dA39C3557Fd88B7aba4aB00B780356e2089Aba9").unwrap(),
            xpub.get_address(11).unwrap()
        );
        assert_eq!(
            EthereumAddress::from_str("0x07d916E246341d241ECa12ae443a986D6f1CD626").unwrap(),
            xpub.get_address(23).unwrap()
        );
    }
}

