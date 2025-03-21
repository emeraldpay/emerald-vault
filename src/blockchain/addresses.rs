use crate::blockchain::bitcoin::{XPub, AddressType};
use crate::error::VaultError;
use bitcoin::{Address as BitcoinAddress, PublicKey, Network, ScriptBuf, CompressedPublicKey, NetworkKind};
use bitcoin::blockdata::opcodes::all::{OP_PUSHBYTES_0};
use bitcoin::blockdata::script::Builder;
use crate::blockchain::ethereum::EthereumAddress;
use crate::sign::bitcoin::DEFAULT_SECP256K1;
use bitcoin::bip32::ChildNumber;
use bitcoin_hashes::{hash160};
use emerald_hwkey::errors::HWKeyError;

pub trait AddressFromPub<T> {
    fn create(pubkey: PublicKey, address_type: &AddressType, mainnet: bool) -> Result<T, ()>;
}

pub trait AddressCast<T> {
    fn from_ethereum_address(x: EthereumAddress) -> Option<T>;
    fn from_bitcoin_address(x: BitcoinAddress) -> Option<T>;
}

fn segwit_script(key: &PublicKey) -> ScriptBuf {
    //
    // see https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
    //
    let pubkey_hash = hash160::Hash::hash(&key.to_bytes());
    Builder::new()
        .push_opcode(OP_PUSHBYTES_0)
        .push_slice(pubkey_hash.as_byte_array())
        .into_script()
}

impl AddressFromPub<BitcoinAddress> for BitcoinAddress {
    fn create(pubkey: PublicKey, address_type: &AddressType, mainnet: bool) -> Result<BitcoinAddress, ()> {
        let network = if mainnet {
            Network::Bitcoin
        } else {
            Network::Testnet
        };
        let address = match address_type {
            AddressType::P2WPKH => {
                let compressed = CompressedPublicKey::try_from(pubkey.clone())
                    .map_err(|_| HWKeyError::CryptoError("Invalid public key".to_string())).unwrap();
                BitcoinAddress::p2wpkh(&compressed, network)
            },
            AddressType::P2WPKHinP2SH => BitcoinAddress::p2sh(&segwit_script(&pubkey), network).map_err(|_| ())?,
            AddressType::P2PKH => BitcoinAddress::p2pkh(&pubkey, network),
            _ => return Err(())
        };
        Ok(address)
    }
}

impl AddressCast<BitcoinAddress> for BitcoinAddress {
    fn from_ethereum_address(_: EthereumAddress) -> Option<BitcoinAddress> {
        None
    }

    fn from_bitcoin_address(x: BitcoinAddress) -> Option<BitcoinAddress> {
        Some(x)
    }
}

impl AddressFromPub<EthereumAddress> for EthereumAddress {
    fn create(pubkey: PublicKey, _: &AddressType, _: bool) -> Result<EthereumAddress, ()> {
        Ok(EthereumAddress::from(pubkey))
    }
}

impl AddressCast<EthereumAddress> for EthereumAddress {
    fn from_ethereum_address(x: EthereumAddress) -> Option<EthereumAddress> {
        Some(x)
    }

    fn from_bitcoin_address(_: BitcoinAddress) -> Option<EthereumAddress> {
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
        T::create(PublicKey::new(pk.public_key), &self.address_type, self.value.network == NetworkKind::Main)
            .map_err(|_| VaultError::PublicKeyUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::bitcoin::{AddressType, XPub};
    use std::str::FromStr;
    use bitcoin::{Address, PublicKey};
    use crate::addresses::segwit_script;
    use crate::EthereumAddress;
    use crate::blockchain::addresses::AddressFromPub;

    // test seed: anchor badge zone antique book leader cupboard wolf confirm average unable nut tortoise dinner private

    #[test]
    fn gets_bitcoin_address_p2wpkh() {
        //m/84'/0'/0'/0/0
        let xpub = XPub::from_str("zpub6sZND4YD5Xui5KDmcXf7sLccderNJ5fJvNXHrrUuTuoSPbccHgJmk8sDzSi1k2nTRG31VuVe6Ydf7BWHj1TxPPKQk8bGqN2S7uMqDxNL7LS").unwrap();

        assert_eq!(
            Address::from_str("bc1q8redwn9d9qr0nkp7ah367u56ufxjprf0lvp7an").unwrap().assume_checked(),
            xpub.get_address(0).unwrap()
        );
        assert_eq!(
            Address::from_str("bc1q8lv69l5lnnpals79jqn78a3fy2eh8t9uls828y").unwrap().assume_checked(),
            xpub.get_address(1).unwrap()
        );
        assert_eq!(
            Address::from_str("bc1qetmge23y3ns900ktwruhqrqwdrp5983lt4wsw0").unwrap().assume_checked(),
            xpub.get_address(10).unwrap()
        );
        assert_eq!(
            Address::from_str("bc1q5gumd2vpylwt5swlmsuqewjr4vx2rwvqhf2jea").unwrap().assume_checked(),
            xpub.get_address(101).unwrap()
        );
    }

    #[test]
    fn gets_bitcoin_address_p2pk() {
        //m/44'/0'/0'/0/0
        let xpub = XPub::from_str("xpub6Ea6xDJzr3fkWRvX9NE8QhgkoTacx2QutYxVHye1XKbxumtHWKpQ11ojaGdU1T31f1HhnqRHpZrPbM3nL9ZxvqxxiphE8PBtBfz1wBNUM93").unwrap();

        assert_eq!(
            Address::from_str("14tjEiXwvUTHSwi6QEBJ68DGT2M69kNceg").unwrap().assume_checked(),
            xpub.get_address(0).unwrap()
        );

        assert_eq!(
            Address::from_str("153B6dLR1Pdo39P3UKXscoC5Vx4CLRDcRm").unwrap().assume_checked(),
            xpub.get_address(1).unwrap()
        );

        assert_eq!(
            Address::from_str("16CyhX3fZsbnTkDdQoTFYBZJk38se3dH1p").unwrap().assume_checked(),
            xpub.get_address(17).unwrap()
        );

        assert_eq!(
            Address::from_str("1BnxciMhoVyjjESxaiV6qrzcPFsi1xsnTR").unwrap().assume_checked(),
            xpub.get_address(101).unwrap()
        );
    }

    #[test]
    fn generate_segwit_script() {
        // test vector from https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki

        let pubkey = PublicKey::from_slice(
            hex::decode("03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f").unwrap().as_slice()
        ).expect("invalid pk");

        assert_eq!(
            hex::encode(segwit_script(&pubkey).as_bytes()),
            "001438971f73930f6c141d977ac4fd4a727c854935b3"
        );
    }

    #[test]
    fn segwit_address_from_pubkey() {
        let pubkey = PublicKey::from_slice(
            hex::decode("03dda55c85ca52a2cc6a132fa79bcea32bc96f109b0c81ab656bc66175d131de95").unwrap().as_slice()
        ).expect("invalid pk");

        assert_eq!(
            Address::from_str("36rFv1P1PbnVz2VwhmNcJ9oP3CmWz3YycS").unwrap().assume_checked(),
            Address::create(pubkey, &AddressType::P2WPKHinP2SH, true).expect("cannot create")
        );
    }

    #[test]
    fn gets_bitcoin_address_segwit() {
        //m/49'/0'/0'/0/0
        let xpub = XPub::from_str("ypub6ZkM2f39PDmJ7fXV5Zf4FDHpdsN42wwoEUV1NmmxqEjf1DcgwkTk2D7kxjaUx9FrzfoHCq3szX3v858mKuhfTSVjVi8igLwL7kD6QVn8BhL").unwrap();

        assert_eq!(
            Address::from_str("36rFv1P1PbnVz2VwhmNcJ9oP3CmWz3YycS").unwrap().assume_checked(),
            xpub.get_address(0).unwrap()
        );

        assert_eq!(
            Address::from_str("3MHwyisRg83ECfzo2kwxSpPbVfwAX3B9W4").unwrap().assume_checked(),
            xpub.get_address(1).unwrap()
        );

        assert_eq!(
            Address::from_str("3FV15ViXkw3vh4gcHBBAsYU6XzhnKb9ZjF").unwrap().assume_checked(),
            xpub.get_address(17).unwrap()
        );

        assert_eq!(
            Address::from_str("3C9bvGNvFePHpu7SRZfjz3rdFAaD9bCvQ1").unwrap().assume_checked(),
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

