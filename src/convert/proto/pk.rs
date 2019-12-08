use std::convert::{TryFrom, TryInto};
use protobuf::{parse_from_bytes, Message};
use std::str::FromStr;
use uuid::Uuid;
use crate::proto::{
    crypto::{
      Encrypted as proto_Encrypted
    },
    pk::{
        PrivateKey as proto_PrivateKey,
        EthereumPrivateKey as proto_EthereumPrivateKey,
        EthereumPK3 as proto_EthereumPK3,
        HDKey as proto_HDKey
    }
};
use crate::convert::{
    ethereum::EthereumJsonV3File,
    proto::{
        types::HasUuid,
        crypto::{
            Encrypted,
        }
    }
};
use crate::core::{Address, PrivateKey as core_PK};
use crate::crypto::error::CryptoError;
use crate::storage::error::VaultError;


pub struct PrivateKeyHolder {
    pub id: Uuid,
    pub pk: PrivateKeyType
}

pub enum PrivateKeyType {
    EthereumPk(EthereumPk3),
    EthereumSeed(SeedReference)
}

pub struct EthereumPk3 {
    pub address: Option<Address>,
    pub key: Encrypted
}

pub struct SeedReference {
    pub id: Uuid,
    pub hdpath: String
}

impl From<&EthereumJsonV3File> for EthereumPk3 {
    fn from(json: &EthereumJsonV3File) -> Self {
        EthereumPk3 {
            address: json.address,
            key: Encrypted::from(json)
        }
    }
}

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for PrivateKeyHolder {
    type Error = VaultError;
    fn try_from(data: &[u8]) -> Result<Self, VaultError> {
        let m = parse_from_bytes::<proto_PrivateKey>(data)?;
        if m.has_ethereum() {
            let pk = m.get_ethereum();
            if pk.has_pk() {
                let pk = pk.get_pk();
                let key = match &pk.value.clone().into_option() {
                    Some(v) => Encrypted::try_from(v),
                    None => Err(VaultError::InvalidDataError("Encryption is not specified".to_string()))
                }?;
                let address = match Address::from_str(pk.get_address()) {
                    Ok(a) => Some(a),
                    Err(_) => None
                };
                let result = EthereumPk3 {
                    address,
                    key
                };
                let pk = PrivateKeyType::EthereumPk(result);
                let result = PrivateKeyHolder { id: Uuid::from_str(m.get_id())?, pk };
                Ok(result)
            } else {
                Err(VaultError::UnsupportedDataError("PK is empty".to_string()))
            }
        } else {
            Err(VaultError::UnsupportedDataError("Unsupported type of PK".to_string()))
        }
    }
}

/// Read from Protobuf bytes
impl TryFrom<Vec<u8>> for PrivateKeyHolder {
    type Error = VaultError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        PrivateKeyHolder::try_from(value.as_slice())
    }
}


/// Write as Protobuf bytes
impl TryFrom<PrivateKeyHolder> for Vec<u8> {
    type Error = VaultError;

    fn try_from(value: PrivateKeyHolder) -> Result<Self, Self::Error> {
        let mut result = proto_PrivateKey::default();
        let mut ethereum = proto_EthereumPrivateKey::default();
        match &value.pk {
            PrivateKeyType::EthereumPk(it) => {
                let mut ethereum_pk3 = proto_EthereumPK3::default();
                result.set_id(value.id.to_string());
                match it.address {
                    Some(address) => ethereum_pk3.set_address(address.to_string()),
                    None => {}
                };
                ethereum_pk3.set_value(proto_Encrypted::try_from(&it.key)?);
                ethereum.set_pk(ethereum_pk3);
            },
            PrivateKeyType::EthereumSeed(it) => {
                let mut hdkey = proto_HDKey::new();
                hdkey.set_path(it.hdpath.clone());
                hdkey.set_seed_id(it.id.to_string());
                ethereum.set_hd(hdkey);
            }
        }
        result.set_ethereum(ethereum);
        result.write_to_bytes()
            .map_err(|e| VaultError::from(e))
    }
}

impl HasUuid for PrivateKeyHolder {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl PrivateKeyHolder {
    pub fn generate_id(&mut self) {
        self.id = Uuid::new_v4();
    }
}
