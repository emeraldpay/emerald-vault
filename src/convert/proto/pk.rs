use std::convert::{TryFrom};
use protobuf::{parse_from_bytes, Message};
use std::str::FromStr;
use uuid::Uuid;
use crate::{
    core::{Address},
    proto::{
        crypto::{
            Encrypted as proto_Encrypted
        },
        pk::{
            PrivateKey as proto_PrivateKey,
            EthereumPrivateKey as proto_EthereumPrivateKey,
            EthereumPK3 as proto_EthereumPK3
        }
    },
    storage::error::VaultError,
    structs::{
        crypto::{
            Encrypted,
        },
        pk::{
            PrivateKeyHolder, EthereumPk3, PrivateKeyType
        }
    }
};

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
            }
        }
        result.set_ethereum(ethereum);
        result.write_to_bytes()
            .map_err(|e| VaultError::from(e))
    }
}
