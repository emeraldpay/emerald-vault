use crate::{
    blockchain::EthereumAddress,
    convert::error::ConversionError,
    proto::{
        common::FileType as proto_FileType,
        crypto::Encrypted as proto_Encrypted,
        pk::{
            EthereumPK3 as proto_EthereumPK3,
            EthereumPrivateKey as proto_EthereumPrivateKey,
            PrivateKey as proto_PrivateKey,
        },
    },
    structs::{
        crypto::Encrypted,
        pk::{EthereumPk3, PrivateKeyHolder, PrivateKeyType},
    },
};
use chrono::{TimeZone, Utc};
use protobuf::{parse_from_bytes, Message};
use std::{convert::TryFrom, str::FromStr};
use uuid::Uuid;

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for PrivateKeyHolder {
    type Error = ConversionError;
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let m = parse_from_bytes::<proto_PrivateKey>(data)?;
        if m.has_ethereum() {
            let pk = m.get_ethereum();
            if pk.has_pk() {
                let pk = pk.get_pk();
                let key = match &pk.value.clone().into_option() {
                    Some(v) => Encrypted::try_from(v),
                    None => Err(ConversionError::FieldIsEmpty("encrypted".to_string())),
                }?;
                let address = match EthereumAddress::from_str(pk.get_address()) {
                    Ok(a) => Some(a),
                    Err(_) => None,
                };
                let result = EthereumPk3 { address, key };
                let pk = PrivateKeyType::EthereumPk(result);
                let created_at = Utc
                    .timestamp_millis_opt(m.get_created_at() as i64)
                    .single()
                    .unwrap_or_else(|| Utc.timestamp_millis(0));
                let result = PrivateKeyHolder {
                    id: Uuid::from_slice(m.get_id())
                        .map_err(|_| ConversionError::InvalidFieldValue("id".to_string()))?,
                    pk,
                    created_at,
                };
                Ok(result)
            } else {
                Err(ConversionError::FieldIsEmpty("pk".to_string()))
            }
        } else {
            Err(ConversionError::InvalidFieldValue("pk".to_string()))
        }
    }
}

/// Read from Protobuf bytes
impl TryFrom<Vec<u8>> for PrivateKeyHolder {
    type Error = ConversionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        PrivateKeyHolder::try_from(value.as_slice())
    }
}

/// Write as Protobuf bytes
impl TryFrom<PrivateKeyHolder> for Vec<u8> {
    type Error = ConversionError;

    fn try_from(value: PrivateKeyHolder) -> Result<Self, Self::Error> {
        let mut result = proto_PrivateKey::default();
        result.set_file_type(proto_FileType::FILE_PK);
        result.set_id(value.id.as_bytes().to_vec());
        let mut ethereum = proto_EthereumPrivateKey::default();
        match &value.pk {
            PrivateKeyType::EthereumPk(it) => {
                let mut ethereum_pk3 = proto_EthereumPK3::default();
                match it.address {
                    Some(address) => ethereum_pk3.set_address(address.to_string()),
                    None => {}
                };
                ethereum_pk3.set_value(proto_Encrypted::try_from(&it.key)?);
                ethereum.set_pk(ethereum_pk3);
            }
        }
        result.set_ethereum(ethereum);
        result.set_created_at(value.created_at.timestamp_millis() as u64);
        result
            .write_to_bytes()
            .map_err(|e| ConversionError::from(e))
    }
}

#[cfg(test)]
mod tests {
    use crate::{proto::pk::PrivateKey as proto_PrivateKey, structs::pk::PrivateKeyHolder};
    use chrono::{TimeZone, Utc};
    use protobuf::{parse_from_bytes, Message, ProtobufEnum};
    use std::{
        convert::{TryFrom, TryInto},
        str::FromStr,
    };
    use uuid::Uuid;

    #[test]
    fn write_as_protobuf() {
        let mut pk = PrivateKeyHolder::generate_ethereum_raw("test").unwrap();
        pk.id = Uuid::from_str("18ba0447-81f3-40d7-bab1-e74de07a1001").unwrap();
        pk.created_at = Utc.timestamp_millis(1592624592679);

        let b: Vec<u8> = pk.try_into().unwrap();
        assert!(b.len() > 0);
        let act = parse_from_bytes::<proto_PrivateKey>(b.as_slice()).unwrap();
        assert_eq!(act.get_file_type().value(), 2);
        assert_eq!(
            Uuid::from_slice(act.get_id()).unwrap(),
            Uuid::from_str("18ba0447-81f3-40d7-bab1-e74de07a1001").unwrap()
        );
        assert!(act.has_ethereum());
        assert_eq!(act.created_at, 1592624592679);
    }

    #[test]
    fn write_and_read() {
        let mut pk = PrivateKeyHolder::generate_ethereum_raw("test").unwrap();
        pk.id = Uuid::from_str("18ba0447-81f3-40d7-bab1-e74de07a1001").unwrap();
        pk.created_at = Utc.timestamp_millis(1592624592679);

        let b: Vec<u8> = pk.try_into().unwrap();
        assert!(b.len() > 0);
        let act = PrivateKeyHolder::try_from(b).unwrap();
        assert_eq!(act.id.to_string(), "18ba0447-81f3-40d7-bab1-e74de07a1001");
        assert!(act.decrypt("test").is_ok());
        assert_eq!(act.created_at, Utc.timestamp_millis(1592624592679));
    }

    #[test]
    fn ignore_big_created_at() {
        let pk = PrivateKeyHolder::generate_ethereum_raw("test").unwrap();
        let tmp: Vec<u8> = pk.try_into().unwrap();
        let mut m = parse_from_bytes::<proto_PrivateKey>(tmp.as_slice()).unwrap();
        m.set_created_at((i64::MAX as u64) + 100);

        let buf = m.write_to_bytes().unwrap();
        let act = PrivateKeyHolder::try_from(buf).unwrap();
        assert_eq!(act.created_at.timestamp_millis(), 0);
    }
}
