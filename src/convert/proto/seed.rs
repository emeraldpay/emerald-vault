use crate::convert::error::ConversionError;
use crate::{
    proto::{
        crypto::Encrypted as proto_Encrypted,
        seed::{
            HDPathFingerprint as proto_HDFingerprint, LedgerSeed as proto_LedgerSeed,
            Seed as proto_Seed, Seed_oneof_seed_source as proto_SeedType,
        },
        common::FileType as proto_FileType
    },
    structs::{
        crypto::Encrypted,
        seed::{Bytes256, FingerprintType, HDPathFingerprint, LedgerSource, Seed, SeedSource},
    },
};
use protobuf::{parse_from_bytes, Message};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use uuid::Uuid;
use hdpath::StandardHDPath;

/// Read from Protobuf message
impl TryFrom<&proto_LedgerSeed> for LedgerSource {
    type Error = ConversionError;

    fn try_from(value: &proto_LedgerSeed) -> Result<Self, Self::Error> {
        let fp = value.get_fingerprints();
        let fingerprints = if fp.is_empty() {
            Vec::new()
        } else {
            let mut fingerprints = Vec::new();
            for f in value.get_fingerprints() {
                let data = Bytes256::try_from(f.get_fingerprint())
                    .map_err(|_| ConversionError::InvalidFieldValue("fingerprint".to_string()))?;
                let value = HDPathFingerprint {
                    hd_path: StandardHDPath::try_from(f.get_path())
                        .map_err(|_| ConversionError::InvalidFieldValue("hd_path".to_string()))?,
                    value: FingerprintType::AddressSha256(data),
                };
                fingerprints.push(value)
            }
            fingerprints
        };
        let result = LedgerSource { fingerprints };
        Ok(result)
    }
}

/// Write as Protobuf message
impl TryFrom<LedgerSource> for proto_LedgerSeed {
    type Error = ConversionError;

    fn try_from(value: LedgerSource) -> Result<Self, Self::Error> {
        let mut m = proto_LedgerSeed::new();
        if m.get_fingerprints().len() > 0 {
            let fingerprings: Vec<proto_HDFingerprint> = value
                .fingerprints
                .iter()
                .map(|f| {
                    let mut pf = proto_HDFingerprint::new();
                    pf.set_path(f.hd_path.to_string());
                    match f.value {
                        FingerprintType::AddressSha256(b) => pf.set_fingerprint(b.into()),
                    }
                    pf
                })
                .collect();

            m.set_fingerprints(protobuf::RepeatedField::from_vec(fingerprings));
        }
        Ok(m)
    }
}

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for Seed {
    type Error = ConversionError;
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let m = parse_from_bytes::<proto_Seed>(data)?;
        let source = match &m.seed_source {
            Some(source) => match source {
                proto_SeedType::bytes(e) => SeedSource::Bytes(Encrypted::try_from(e)?),
                proto_SeedType::ledger(l) => SeedSource::Ledger(LedgerSource::try_from(l)?),
            },
            None => return Err(ConversionError::FieldIsEmpty("seed_source".to_string())),
        };
        let result = Seed {
            id: Uuid::from_bytes(m.get_id())
                .map_err(|_| ConversionError::InvalidFieldValue("id".to_string()))?,
            source,
        };
        Ok(result)
    }
}

/// Read from Protobuf bytes
impl TryFrom<Vec<u8>> for Seed {
    type Error = ConversionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Seed::try_from(value.as_slice())
    }
}

/// Write as Protobuf bytes
impl TryFrom<Seed> for Vec<u8> {
    type Error = ConversionError;

    fn try_from(value: Seed) -> Result<Self, Self::Error> {
        let mut m = proto_Seed::new();
        m.set_file_type(proto_FileType::FILE_SEED);
        m.set_id(value.id.as_bytes().to_vec());
        match value.source {
            SeedSource::Bytes(s) => m.set_bytes(proto_Encrypted::try_from(&s)?),
            SeedSource::Ledger(s) => m.set_ledger(s.try_into()?),
        }
        m.write_to_bytes().map_err(|e| ConversionError::from(e))
    }
}

#[cfg(test)]
mod tests {
    use crate::structs::crypto::Encrypted;
    use crate::structs::seed::{LedgerSource, Seed, SeedSource};
    use std::convert::{TryFrom, TryInto};
    use uuid::Uuid;
    use protobuf::{parse_from_bytes, ProtobufEnum};
    use std::str::FromStr;
    use crate::proto::seed::Seed as proto_Seed;

    #[test]
    fn write_as_protobuf() {
        let seed = Seed {
            id: Uuid::from_str("18ba0447-81f3-40d7-bab1-e74de07a1001").unwrap(),
            source: SeedSource::Bytes(Encrypted::encrypt(b"test".to_vec(), "test").unwrap()),
        };

        let b: Vec<u8> = seed.clone().try_into().unwrap();
        assert!(b.len() > 0);
        let act = parse_from_bytes::<proto_Seed>(b.as_slice()).unwrap();
        assert_eq!(act.get_file_type().value(), 3);
        assert_eq!(Uuid::from_bytes(act.get_id()).unwrap(), Uuid::from_str("18ba0447-81f3-40d7-bab1-e74de07a1001").unwrap());
        assert!(act.has_bytes());
    }

    #[test]
    fn write_and_read_bytes() {
        let seed = Seed {
            id: Uuid::new_v4(),
            source: SeedSource::Bytes(Encrypted::encrypt(b"test".to_vec(), "test").unwrap()),
        };
        let seed_id = seed.id.clone();
        let buf: Vec<u8> = seed.try_into().unwrap();
        let seed_act = Seed::try_from(buf).unwrap();

        assert_eq!(seed_act.id, seed_id);
        match seed_act.source {
            SeedSource::Bytes(e) => e,
            _ => panic!("Not bytes"),
        };
    }

    #[test]
    fn write_and_read_ledger() {
        let seed = Seed {
            id: Uuid::new_v4(),
            source: SeedSource::Ledger(LedgerSource {
                fingerprints: vec![],
            }),
        };
        let seed_id = seed.id.clone();
        let buf: Vec<u8> = seed.try_into().unwrap();
        let seed_act = Seed::try_from(buf).unwrap();

        assert_eq!(seed_act.id, seed_id);
        match seed_act.source {
            SeedSource::Ledger(v) => v,
            _ => panic!("Not ledger"),
        };
    }
}
