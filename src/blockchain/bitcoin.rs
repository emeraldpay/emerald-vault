use crate::structs::wallet::WalletEntry;
use bitcoin::{OutPoint, TxOut, Script, Network, PublicKey};
use hdpath::StandardHDPath;
use crate::structs::seed::{SeedRef, Seed, SeedSource};
use crate::storage::vault::VaultStorage;
use uuid::Uuid;
use std::collections::HashMap;
use crate::storage::error::VaultError;
use std::rc::Rc;
use bitcoin::util::bip32::{ExtendedPubKey, ChildNumber, ChainCode, Fingerprint};
use bitcoin::util::{base58};
use byteorder::{BigEndian, ReadBytesExt};
use crate::convert::error::ConversionError;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InputReference {
    pub output: OutPoint,
    pub script_source: InputScriptSource,
    pub expected_value: u64,
    pub sequence: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InputScriptSource {
    HD(Uuid, StandardHDPath)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinTransferProposal {
    pub network: Network,
    pub seed: Vec<Seed>,
    pub keys: KeyMapping,
    pub input: Vec<InputReference>,
    pub output: Vec<TxOut>,
    pub change: WalletEntry,
    pub expected_fee: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyMapping(HashMap<Uuid, String>);

impl KeyMapping {
    pub fn single(id: Uuid, password: String) -> KeyMapping {
        let mut instance = HashMap::with_capacity(1);
        instance.insert(id, password);
        KeyMapping(instance)
    }

    pub fn get_password(&self, id: &Uuid) -> Result<String, VaultError> {
        match self.0.get(id) {
            Some(p) => Ok(p.clone()),
            None => Err(VaultError::PasswordRequired)
        }
    }
}

impl BitcoinTransferProposal {
    pub fn get_seed(&self, id: &Uuid) -> Option<Seed> {
        self.seed.iter()
            .find(|s| s.id.eq(id))
            .map(|x| x.clone())
    }
}

pub fn parse_xpub(value: &str, network: Network) -> Result<ExtendedPubKey, ConversionError> {
    let data = base58::from_check(value).map_err(|_| ConversionError::InvalidBase58)?;

    if data.len() != 78 {
        return Err(ConversionError::InvalidLength);
    }

    //
    // versions: https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
    //
    let mut version_bytes = &data[0..4];
    let version = version_bytes.read_u32::<BigEndian>().unwrap();
    let is_mainnet = version == 0x0488b21e //xpub
        || version == 0x049d7cb2 //ypub
        || version == 0x0295b43f //Ypub
        || version == 0x04b24746 //zpub
        || version == 0x02aa7ed3 //Zpub
        ;
    let is_testnet = version == 0x043587cf //tpub
        || version == 0x044a5262 // upub
        || version == 0x024289ef // Upub
        || version == 0x045f1cf6 // vpub
        || version == 0x02575483 // Vpub
        ;

    if network == Network::Testnet && is_mainnet {
        return Err(ConversionError::UnsupportedValue("Mainnet xpub for testnet".to_string()))
    }
    if network == Network::Bitcoin && is_testnet {
        return Err(ConversionError::UnsupportedValue("Tesnet xpub for mainnet".to_string()))
    }

    let mut child_num_bytes = &data[9..13];
    let child_num: u32 = child_num_bytes.read_u32::<BigEndian>().unwrap();
    let result = ExtendedPubKey {
        network,
        depth: data[4],
        parent_fingerprint: Fingerprint::from(&data[5..9]),
        child_number: ChildNumber::from(child_num),
        chain_code: ChainCode::from(&data[13..45]),
        public_key: PublicKey::from_slice(&data[45..78]).map_err(|_| ConversionError::OtherError)?,
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use bitcoin::{Script, Network, PublicKey};
    use crate::blockchain::bitcoin::parse_xpub;

    #[test]
    fn parse_xpub_p2pkh() {
        let act = parse_xpub("xpub6DfEZhR1ZBu33KzKqHPA1GCfKPpdB9HWFu5UsA54kB5VL3VN34JogQxYHWtSgrippZHp8s9hL9KrAfdYX1sU6cYRXMhGYuvwepFUooGAef5", Network::Bitcoin).unwrap();
        assert_eq!(act.depth, 4u8);
    }

    #[test]
    fn parse_xpub_p2wpkh() {
        let act = parse_xpub("zpub6tGSDzdnLUJBBBanLhkcTqkc44WzxshiTBiCuZTgz198oQxPxx4kkdRAhQD3TBBieMPkFAfSUvKov7nKQX6cXJxZEU1BTeHVGjyR5EHubqb", Network::Bitcoin).unwrap();
        assert_eq!(act.depth, 4u8);
    }

    #[test]
    fn parse_xpub_p2pkh_testnet() {
        let act = parse_xpub("tpubDFJnjeM57mHkG8LhyzfDwsWYJUWwta4Aq4nPo59hfVGhanWn7h98c2q6WoexVgkHx9Bg2vrAhCQi13tZozsZmrU8ca43c7em3RUvMXbSdHi", Network::Testnet).unwrap();
    }

    #[test]
    fn doesnt_accept_mainnet_xpub_for_test() {
        let act = parse_xpub("xpub6DfEZhR1ZBu33KzKqHPA1GCfKPpdB9HWFu5UsA54kB5VL3VN34JogQxYHWtSgrippZHp8s9hL9KrAfdYX1sU6cYRXMhGYuvwepFUooGAef5", Network::Testnet);
        assert!(act.is_err());

        let act = parse_xpub("zpub6tGSDzdnLUJBBBanLhkcTqkc44WzxshiTBiCuZTgz198oQxPxx4kkdRAhQD3TBBieMPkFAfSUvKov7nKQX6cXJxZEU1BTeHVGjyR5EHubqb", Network::Testnet);
        assert!(act.is_err());
    }

    #[test]
    fn doesnt_accept_test_xpub_for_mainnet() {
        let act = parse_xpub("tpubDFJnjeM57mHkG8LhyzfDwsWYJUWwta4Aq4nPo59hfVGhanWn7h98c2q6WoexVgkHx9Bg2vrAhCQi13tZozsZmrU8ca43c7em3RUvMXbSdHi", Network::Bitcoin);
        assert!(act.is_err());

        let act = parse_xpub("vpub5bQdPwJzPiiAc5scKtK8UbNVHhYHrHp1vHmfpUGQkkDEjSRkkTuCioK3zgGEccy3d7M5coqrSvgzHp66nopWanA2WS7JR3pyXNKUUQ9DPaV", Network::Bitcoin);
        assert!(act.is_err());
    }
}
