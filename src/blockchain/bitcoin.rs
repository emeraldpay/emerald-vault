use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    str::FromStr,
};

use bitcoin::{util::{
    base58,
    bip32::{ChainCode, ChildNumber, ExtendedPubKey, Fingerprint},
}, Network, OutPoint, PublicKey, TxOut, Address};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use hdpath::{StandardHDPath, Purpose, AccountHDPath};
use uuid::Uuid;

use crate::{
    convert::error::ConversionError,
    error::VaultError,
    structs::{seed::Seed, wallet::WalletEntry},
    sign::bitcoin::DEFAULT_SECP256K1
};
use std::cmp::min;
use crate::structs::crypto::GlobalKey;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InputReference {
    pub output: OutPoint,
    pub script_source: InputScriptSource,
    pub expected_value: u64,
    pub sequence: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InputScriptSource {
    HD(Uuid, StandardHDPath),
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
pub struct KeyMapping {
    pub keys: HashMap<Uuid, String>,

    /// reference to a global password if set
    pub global: Option<GlobalKey>,
    pub global_password: Option<String>,
}

impl KeyMapping {
    ///
    /// Create mapping just referencing a single object (PK or Seed).
    /// NOTE: it doesn't use Global Key
    pub fn single(id: Uuid, password: String) -> KeyMapping {
        let mut instance = HashMap::with_capacity(1);
        instance.insert(id, password);
        KeyMapping {
            keys: instance,
            global: None,
            global_password: None,
        }
    }

    ///
    /// Create mapping referencing only a Global Key
    pub fn global(global: GlobalKey, password: String) -> KeyMapping {
        KeyMapping {
            keys: HashMap::new(),
            global: Some(global),
            global_password: Some(password),
        }
    }


    ///
    /// Returns password for the specified object id. It may be a global key if the object doesn't
    /// have an individual password
    pub fn get_password(&self, id: &Uuid) -> Result<String, VaultError> {
        match self.keys.get(id) {
            Some(p) => Ok(p.clone()),
            None => self.global_password.clone().ok_or(VaultError::PasswordRequired),
        }
    }

    ///
    /// Merge two Key Mappings into one.
    pub fn plus(self, other: KeyMapping) -> KeyMapping {
        let mut instance = HashMap::with_capacity(self.keys.len() + other.keys.len());
        for key in self.keys {
            instance.insert(key.0, key.1);
        }
        for key in other.keys {
            instance.insert(key.0, key.1);
        }

        KeyMapping {
            keys: instance,
            global: self.global.or(other.global),
            global_password: self.global_password.or(other.global_password),
        }
    }
}

impl Default for KeyMapping {
    fn default() -> Self {
        KeyMapping {
            keys: HashMap::new(),
            global: None,
            global_password: None,
        }
    }
}

impl BitcoinTransferProposal {
    pub fn get_seed(&self, id: &Uuid) -> Option<Seed> {
        self.seed.iter().find(|s| s.id.eq(id)).map(|x| x.clone())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct XPub {
    pub value: ExtendedPubKey,
    pub address_type: AddressType,
}

#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub enum AddressType {
    /// Pay To Public Key Hash
    /// Legacy address, starts with 1
    P2PKH,
    /// Pay To Script Hash
    /// New type of address, starts with 3
    P2SH,
    P2WPKHinP2SH,
    P2WSHinP2SH,
    /// Pay To Witness Public Key Hash
    /// Bench32 address, with 20 bytes address
    P2WPKH,
    /// Pay To Witness Script Hash
    /// Bench32 address, with 32 bytes address
    P2WSH,
}

impl XPub {

    pub fn standard(xpub: ExtendedPubKey) -> XPub {
        XPub {
            value: xpub,
            address_type: AddressType::P2WPKH
        }
    }

    pub fn is_account(&self) -> bool {
        self.value.depth == 3
    }

    fn for_type(&self, n: u32) -> Result<XPub, VaultError> {
        let result = XPub {
            address_type: self.address_type,
            value: self.value
                .ckd_pub(&DEFAULT_SECP256K1,
                         ChildNumber::from_normal_idx(n)
                             .expect(format!("Failed to get change: {:}", n).as_str()),
                )
                .map_err(|_| VaultError::PublicKeyUnavailable)?,
        };
        Ok(result)
    }

    pub fn for_receiving(&self) -> Result<XPub, VaultError> {
        self.for_type(0)
    }

    pub fn for_change(&self) -> Result<XPub, VaultError> {
        self.for_type(1)
    }

    pub fn find_path(&self, account: &AccountHDPath, address: &Address, limit: u32) -> Option<StandardHDPath> {
        if !self.is_account() {
            return None
        }

        let limit = min(limit, 0x80000000 - 1);

        let receive = self.for_receiving().expect("XPub is not available");
        let change = self.for_change().expect("XPub is not available");

        // TODO always starts from zero, suboptimal for large xpub. need to consider expected position, which may be different for receive and change
        for i in 0..limit {
            if let Ok(act) = receive.get_address::<Address>(i) {
                if act.eq(address) {
                    return Some(account.address_at(0, i).unwrap())
                }
            }

            if let Ok(act) = change.get_address::<Address>(i) {
                if act.eq(address) {
                    return Some(account.address_at(1, i).unwrap())
                }
            }
        }

        return None
    }
}

fn network_value<T>(network: &Network, mainnet: T, testnet: T) -> T {
    if network.eq(&Network::Bitcoin) {
        mainnet
    } else {
        testnet
    }
}

impl AddressType {
    //
    // versions: https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
    //

    pub fn xpub_version(&self, network: &Network) -> u32 {
        match self {
            AddressType::P2PKH => network_value(network, 0x0488b21e, 0x043587cf), // xpub, tpub
            AddressType::P2SH => network_value(network, 0x0488b21e, 0x043587cf),  // xpub, tpub
            AddressType::P2WPKHinP2SH => network_value(network, 0x049d7cb2, 0x044a5262), // ypub, upub
            AddressType::P2WSHinP2SH => network_value(network, 0x0295b43f, 0x024289ef), // Ypub, Upub
            AddressType::P2WPKH => network_value(network, 0x04b24746, 0x045f1cf6), // zpub, vpub
            AddressType::P2WSH => network_value(network, 0x02aa7ed3, 0x02575483),  // Zpub, Vpub
        }
    }

    pub fn xprv_version(&self, network: &Network) -> u32 {
        match self {
            AddressType::P2PKH => network_value(network, 0x0488ade4, 0x04358394), // xprv, tprv
            AddressType::P2SH => network_value(network, 0x0488ade4, 0x04358394),  // xprv, tprv
            AddressType::P2WPKHinP2SH => network_value(network, 0x049d7878, 0x044a4e28), // yprv, uprv
            AddressType::P2WSHinP2SH => network_value(network, 0x0295b005, 0x024285b5), // Yprv, Uprv
            AddressType::P2WPKH => network_value(network, 0x04b2430c, 0x045f18bc), // zprv, vprv
            AddressType::P2WSH => network_value(network, 0x02aa7a99, 0x02575048),  // Zprv, Vprv
        }
    }

    pub fn get_hd_path(&self, account: u32, network: &Network) -> AccountHDPath {
        let coin_type = match network {
            Network::Bitcoin => 0,
            Network::Testnet | Network::Regtest | Network::Signet => 1
        };
        match self {
            AddressType::P2PKH | AddressType::P2SH =>
                AccountHDPath::new(Purpose::Pubkey, coin_type, account),
            AddressType::P2WPKHinP2SH | AddressType::P2WSHinP2SH =>
                AccountHDPath::new(Purpose::ScriptHash, coin_type, account),
            AddressType::P2WPKH | AddressType::P2WSH =>
                AccountHDPath::new(Purpose::Witness, coin_type, account),
        }
    }
}

impl TryFrom<&Purpose> for AddressType {
    type Error = VaultError;

    fn try_from(value: &Purpose) -> Result<Self, Self::Error> {
        match value {
            Purpose::Witness => Ok(AddressType::P2WPKH),
            Purpose::ScriptHash => Ok(AddressType::P2WPKHinP2SH),
            Purpose::Pubkey => Ok(AddressType::P2PKH),
            _ => Err(VaultError::ConversionError(ConversionError::UnsupportedValue(value.as_value().as_number().to_string())))
        }
    }
}

impl TryFrom<Purpose> for AddressType {
    type Error = VaultError;

    fn try_from(value: Purpose) -> Result<Self, Self::Error> {
        AddressType::try_from(&value)
    }
}

impl TryFrom<&StandardHDPath> for AddressType {
    type Error = VaultError;

    fn try_from(value: &StandardHDPath) -> Result<Self, Self::Error> {
        AddressType::try_from(value.purpose())
    }
}

impl TryFrom<&AccountHDPath> for AddressType {
    type Error = VaultError;

    fn try_from(value: &AccountHDPath) -> Result<Self, Self::Error> {
        AddressType::try_from(value.purpose())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddressTypeNetwork(Network, AddressType);

impl TryFrom<u32> for AddressTypeNetwork {
    type Error = ConversionError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0488b21e => Ok(AddressTypeNetwork(Network::Bitcoin, AddressType::P2PKH)), //xpub
            0x049d7cb2 => Ok(AddressTypeNetwork(
                Network::Bitcoin,
                AddressType::P2WPKHinP2SH,
            )), //ypub
            0x0295b43f => Ok(AddressTypeNetwork(
                Network::Bitcoin,
                AddressType::P2WSHinP2SH,
            )), //Ypub
            0x04b24746 => Ok(AddressTypeNetwork(Network::Bitcoin, AddressType::P2WPKH)), //zpub
            0x02aa7ed3 => Ok(AddressTypeNetwork(Network::Bitcoin, AddressType::P2WSH)), //Zpub

            0x043587cf => Ok(AddressTypeNetwork(Network::Testnet, AddressType::P2PKH)), //tpub
            0x044a5262 => Ok(AddressTypeNetwork(
                Network::Testnet,
                AddressType::P2WPKHinP2SH,
            )), //upub
            0x024289ef => Ok(AddressTypeNetwork(
                Network::Testnet,
                AddressType::P2WSHinP2SH,
            )), //Upub
            0x045f1cf6 => Ok(AddressTypeNetwork(Network::Testnet, AddressType::P2WPKH)), //vpub
            0x02575483 => Ok(AddressTypeNetwork(Network::Testnet, AddressType::P2WSH)), //Vpub

            _ => Err(ConversionError::UnsupportedValue(hex::encode(
                u32::to_be_bytes(value),
            ))),
        }
    }
}

impl FromStr for XPub {
    type Err = ConversionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let data = base58::from_check(value).map_err(|_| ConversionError::InvalidBase58)?;
        if data.len() != 78 {
            return Err(ConversionError::InvalidLength);
        }
        let mut version_bytes = &data[0..4];
        let version = version_bytes.read_u32::<BigEndian>().unwrap();
        let version: AddressTypeNetwork = version.try_into()?;
        let mut child_num_bytes = &data[9..13];
        let child_num: u32 = child_num_bytes.read_u32::<BigEndian>().unwrap();
        let value = ExtendedPubKey {
            network: version.0,
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number: ChildNumber::from(child_num),
            chain_code: ChainCode::from(&data[13..45]),
            public_key: PublicKey::from_slice(&data[45..78])
                .map_err(|_| ConversionError::OtherError)?.inner,
        };
        Ok(XPub {
            value,
            address_type: version.1,
        })
    }
}

impl ToString for XPub {
    fn to_string(&self) -> String {
        let mut data: Vec<u8> = Vec::with_capacity(78);
        let version = self.address_type.xpub_version(&self.value.network);
        data.write_u32::<BigEndian>(version).expect("Failed to write version");
        data.push(self.value.depth);
        data.extend_from_slice(self.value.parent_fingerprint.as_bytes());
        data.write_u32::<BigEndian>(self.value.child_number.into()).expect("Failed to write child_number");
        data.extend_from_slice(self.value.chain_code.as_bytes());
        data.extend_from_slice(self.value.public_key.serialize().as_ref());
        base58::check_encode_slice(data.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{Network, Address};

    use crate::blockchain::bitcoin::{AddressType, KeyMapping, XPub};
    use hdpath::{AccountHDPath, StandardHDPath, Purpose};
    use std::convert::TryFrom;
    use uuid::Uuid;
    use crate::structs::crypto::GlobalKey;

    #[test]
    fn parse_xpub_p2pkh() {
        let act = XPub::from_str("xpub6DfEZhR1ZBu33KzKqHPA1GCfKPpdB9HWFu5UsA54kB5VL3VN34JogQxYHWtSgrippZHp8s9hL9KrAfdYX1sU6cYRXMhGYuvwepFUooGAef5").unwrap();
        assert_eq!(act.value.depth, 4u8);
        assert_eq!(act.value.network, Network::Bitcoin);
        assert_eq!(act.address_type, AddressType::P2PKH);
    }

    #[test]
    fn parse_xpub_p2wpkh() {
        let act = XPub::from_str("zpub6tGSDzdnLUJBBBanLhkcTqkc44WzxshiTBiCuZTgz198oQxPxx4kkdRAhQD3TBBieMPkFAfSUvKov7nKQX6cXJxZEU1BTeHVGjyR5EHubqb").unwrap();
        assert_eq!(act.value.depth, 4u8);
        assert_eq!(act.value.network, Network::Bitcoin);
        assert_eq!(act.address_type, AddressType::P2WPKH);
    }

    #[test]
    fn parse_xpub_p2wpkh_p2sh() {
        let act = XPub::from_str("ypub6XKWqjEULzxUZ1AaNausD7JFWzg8jKCFmdycJpojoiRLDCNuLxKREUXnvTD26q3AAsiSBDymo2E21yhAiUY8Vrnu4UHQvfTrKRcvzyV2Pd2").unwrap();
        assert_eq!(act.value.depth, 3u8);
        assert_eq!(act.value.network, Network::Bitcoin);
        assert_eq!(act.address_type, AddressType::P2WPKHinP2SH);
    }

    #[test]
    fn encode_xpub_p2wpkh_p2sh() {
        let source = XPub::from_str("ypub6XKWqjEULzxUZ1AaNausD7JFWzg8jKCFmdycJpojoiRLDCNuLxKREUXnvTD26q3AAsiSBDymo2E21yhAiUY8Vrnu4UHQvfTrKRcvzyV2Pd2").unwrap();
        assert_eq!(
            "ypub6XKWqjEULzxUZ1AaNausD7JFWzg8jKCFmdycJpojoiRLDCNuLxKREUXnvTD26q3AAsiSBDymo2E21yhAiUY8Vrnu4UHQvfTrKRcvzyV2Pd2".to_string(),
            source.to_string()
        );
    }

    #[test]
    fn parse_xpub_p2pkh_testnet() {
        let act = XPub::from_str("tpubDFJnjeM57mHkG8LhyzfDwsWYJUWwta4Aq4nPo59hfVGhanWn7h98c2q6WoexVgkHx9Bg2vrAhCQi13tZozsZmrU8ca43c7em3RUvMXbSdHi").unwrap();
        assert_eq!(act.value.network, Network::Testnet);
        assert_eq!(act.address_type, AddressType::P2PKH);
    }

    #[test]
    fn to_string_xpub_p2wpkh() {
        let orig = XPub::from_str("zpub6tGSDzdnLUJBBBanLhkcTqkc44WzxshiTBiCuZTgz198oQxPxx4kkdRAhQD3TBBieMPkFAfSUvKov7nKQX6cXJxZEU1BTeHVGjyR5EHubqb").unwrap();
        let act = orig.to_string();
        assert_eq!(act, "zpub6tGSDzdnLUJBBBanLhkcTqkc44WzxshiTBiCuZTgz198oQxPxx4kkdRAhQD3TBBieMPkFAfSUvKov7nKQX6cXJxZEU1BTeHVGjyR5EHubqb");
    }

    #[test]
    fn to_string_xpub_p2pkh() {
        let orig = XPub::from_str("xpub6DfEZhR1ZBu33KzKqHPA1GCfKPpdB9HWFu5UsA54kB5VL3VN34JogQxYHWtSgrippZHp8s9hL9KrAfdYX1sU6cYRXMhGYuvwepFUooGAef5").unwrap();
        let act = orig.to_string();
        assert_eq!(act, "xpub6DfEZhR1ZBu33KzKqHPA1GCfKPpdB9HWFu5UsA54kB5VL3VN34JogQxYHWtSgrippZHp8s9hL9KrAfdYX1sU6cYRXMhGYuvwepFUooGAef5");
    }

    #[test]
    fn find_path() {
        // seed: dream frog grape this park hungry quarter elbow fluid acid rack knee brown anxiety jewel
        let xpub = XPub::from_str("zpub6qteEGUGgZ9zvHGqSutP8r9S9Sueg17khktxrBR37msaC3MUtw53qehxdcp9GYBKAFxu9FispvDweXg7ipsX6oJZ6tthJfUEjWfSsZuANqP").unwrap();
        let account = AccountHDPath::from_str("m/84'/0'/0'").unwrap();

        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/0'/0'/0/0").unwrap()),
            xpub.find_path(&account, &Address::from_str("bc1qll4sdpqfhj57aufzzvew7ckpvqfszux5ludhqk").unwrap(), 100)
        );
        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/0'/0'/0/1").unwrap()),
            xpub.find_path(&account, &Address::from_str("bc1q50nlkh0ml0ssmxhj8pwtsnvggr0zvgefsxtp0q").unwrap(), 100)
        );
        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/0'/0'/0/10").unwrap()),
            xpub.find_path(&account, &Address::from_str("bc1q29dcvzah8n4kvx62y4m5rakuu25n798686w8ze").unwrap(), 100)
        );
        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/0'/0'/0/51").unwrap()),
            xpub.find_path(&account, &Address::from_str("bc1qpykvymju08ej3tq43pfyp6lf3gucv6xnlhdasy").unwrap(), 100)
        );
        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/0'/0'/0/99").unwrap()),
            xpub.find_path(&account, &Address::from_str("bc1qgtq69f6pa8x5784ka3cvzc6zauhsw6m82galnv").unwrap(), 100)
        );
        assert_eq!(
            None,
            xpub.find_path(&account, &Address::from_str("bc1q8t8mctklx4l8krp7y07l66vtrk3d0fgvjlm87g").unwrap(), 100)
        );
        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/0'/0'/1/0").unwrap()),
            xpub.find_path(&account, &Address::from_str("bc1qre5f3j3w9qgjhjh20sljqz6dwyred2fpug4nhc").unwrap(), 100)
        );
        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/0'/0'/1/11").unwrap()),
            xpub.find_path(&account, &Address::from_str("bc1qk82d259y5vd9zp4vc6r893qzgtms4tfm4gfwhy").unwrap(), 100)
        );
        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/0'/0'/1/77").unwrap()),
            xpub.find_path(&account, &Address::from_str("bc1qf43gxudgwp7vknpeh4zlhwsv6cmqvrfk9djyed").unwrap(), 100)
        );
    }

    #[test]
    fn find_path_testnet() {
        // seed: dream frog grape this park hungry quarter elbow fluid acid rack knee brown anxiety jewel
        let xpub = XPub::from_str("vpub5ZTSU3hrtSgLtVuBKQrKbKw76TJu8Ndy2apQ138CyiEhVmYpjEGbKFGsrv4Yu1jUNA4pDRJWvctdFvRNvsCVrJfVBHHpnygzAXd71f5pdUC").unwrap();
        let account = AccountHDPath::from_str("m/84'/1'/5'").unwrap();

        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/1'/5'/0/2").unwrap()),
            xpub.find_path(&account, &Address::from_str("tb1q7v6nnp057hdlwtu6uzqedd43q9zqc5w82sar5w").unwrap(), 100)
        );
        assert_eq!(
            Some(StandardHDPath::from_str("m/84'/1'/5'/1/7").unwrap()),
            xpub.find_path(&account, &Address::from_str("tb1q2p4yhftnwe4ft0nztadeqtn9wzequpwzv3puz0").unwrap(), 100)
        );
    }

    #[test]
    fn correct_address_type() {
        assert_eq!(AddressType::P2PKH, AddressType::try_from(Purpose::Pubkey).unwrap());
        assert_eq!(AddressType::P2WPKHinP2SH, AddressType::try_from(Purpose::ScriptHash).unwrap());
        assert_eq!(AddressType::P2WPKH, AddressType::try_from(Purpose::Witness).unwrap());
    }

    #[test]
    fn merge_two_keymappings() {
        let m1 = KeyMapping::single(Uuid::from_str("21f05b67-378a-40ac-9db9-fa4d4f1cd6b2").unwrap(), "test-1".to_string());
        let m2 = KeyMapping::single(Uuid::from_str("f515cbba-6261-44fc-8c90-73a183d235c7").unwrap(), "test-2".to_string());

        let m3 = m1.plus(m2);

        assert_eq!(m3.get_password(&Uuid::from_str("21f05b67-378a-40ac-9db9-fa4d4f1cd6b2").unwrap()).unwrap(), "test-1".to_string());
        assert_eq!(m3.get_password(&Uuid::from_str("f515cbba-6261-44fc-8c90-73a183d235c7").unwrap()).unwrap(), "test-2".to_string());
    }

    #[test]
    fn merge_keymapping_with_global() {
        let m1 = KeyMapping::single(Uuid::from_str("21f05b67-378a-40ac-9db9-fa4d4f1cd6b2").unwrap(), "test-1".to_string());
        let global = GlobalKey::generate("test-2".as_bytes()).unwrap();
        let m2 = KeyMapping::global(global.clone(), "test-2".to_string());

        let m3 = m1.plus(m2);

        assert_eq!(m3.get_password(&Uuid::from_str("21f05b67-378a-40ac-9db9-fa4d4f1cd6b2").unwrap()).unwrap(), "test-1".to_string());
        assert_eq!(m3.global, Some(global));
        assert_eq!(m3.global_password, Some("test-2".to_string()));
    }

    #[test]
    fn use_global_key() {
        let global = GlobalKey::generate("test-2".as_bytes()).unwrap();
        let m = KeyMapping::global(global, "test-g".to_string());

        assert_eq!(m.get_password(&Uuid::from_str("21f05b67-378a-40ac-9db9-fa4d4f1cd6b2").unwrap()).unwrap(), "test-g".to_string());
        assert_eq!(m.get_password(&Uuid::from_str("f515cbba-6261-44fc-8c90-73a183d235c7").unwrap()).unwrap(), "test-g".to_string());
    }
}
