use uuid::Uuid;
use crate::convert::proto::crypto::Encrypted;
use crate::proto::{
    crypto::{
        Encrypted as proto_Encrypted
    },
    seed::{
        Seed as proto_Seed,
        Seed_oneof_seed_source as proto_SeedType,
        LedgerSeed as proto_LedgerSeed,
        HDPathFingerprint as proto_HDFingerprint,
        HDPathFingerprint_Type as proto_HDFingerprintType
    }
};
use std::convert::{TryFrom, TryInto};
use crate::storage::error::VaultError;
use std::str::FromStr;
use protobuf::{parse_from_bytes, Message};
use crate::convert::proto::types::HasUuid;
use crate::Address;
use sha2::Digest;

byte_array_struct!(Bytes256, 32);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Seed {
    pub id: Uuid,
    pub source: SeedSource
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SeedSource {
    Bytes(Encrypted),
    Ledger(LedgerSource)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LedgerSource {
    pub fingerprints: Vec<HDPathFingerprint>
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HDPathFingerprint {
    pub hd_path: String,
    pub value: FingerprintType
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FingerprintType {
    AddressSha256(Bytes256)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SeedRef {
    pub seed_id: Uuid,
    pub hd_path: String
}

// ----

impl HDPathFingerprint {
    pub fn from_address(hd_path: String, address: &Address) -> HDPathFingerprint {
        let hash = sha2::Sha256::digest(address);
        let f = Bytes256::try_from(hash.as_slice()).unwrap();
        HDPathFingerprint {
            hd_path: hd_path,
            value: FingerprintType::AddressSha256(f)
        }
    }
}

// ----

/// Read from Protobuf message
impl TryFrom<&proto_LedgerSeed> for LedgerSource {
    type Error = VaultError;

    fn try_from(value: &proto_LedgerSeed) -> Result<Self, Self::Error> {
        let fp = value.get_fingerprints();
        if fp.is_empty() {
            return Err(VaultError::InvalidDataError("Empty fingerprints".to_string()))
        }
        let mut fingerprints = Vec::new();
        for f in value.get_fingerprints() {
            let data = Bytes256::try_from(f.get_fingerprint())?;
            let value = HDPathFingerprint {
                hd_path: f.get_path().to_string(),
                value: FingerprintType::AddressSha256(data)
            };
            fingerprints.push(value)
        }
        let result = LedgerSource { fingerprints };
        Ok(result)
    }
}

/// Write as Protobuf message
impl TryFrom<LedgerSource> for proto_LedgerSeed {
    type Error = VaultError;

    fn try_from(value: LedgerSource) -> Result<Self, Self::Error> {
        let mut m = proto_LedgerSeed::new();
        let fingerprings: Vec<proto_HDFingerprint> = value.fingerprints.iter()
            .map(|f| {
                let mut pf = proto_HDFingerprint::new();
                pf.set_path(f.hd_path.clone());
                match f.value {
                    FingerprintType::AddressSha256(b) => pf.set_fingerprint(b.into())
                }
                pf
            })
            .collect();

        m.set_fingerprints(protobuf::RepeatedField::from_vec(fingerprings));
        Ok(m)
    }
}

/// Read from Protobuf bytes
impl TryFrom<&[u8]> for Seed {
    type Error = VaultError;
    fn try_from(data: &[u8]) -> Result<Self, VaultError> {
        let m = parse_from_bytes::<proto_Seed>(data)?;
        let source = match &m.seed_source {
            Some(source) => match source {
                proto_SeedType::bytes(e) => SeedSource::Bytes(
                    Encrypted::try_from(e)?
                ),
                proto_SeedType::ledger(l) => SeedSource::Ledger(
                    LedgerSource::try_from(l)?
                )
            },
            None => return Err(VaultError::InvalidDataError("Seed is not set".to_string()))
        };
        let result = Seed {
            id: Uuid::from_str(m.get_id())?,
            source
        };
        Ok(result)
    }
}

/// Read from Protobuf bytes
impl TryFrom<Vec<u8>> for Seed {
    type Error = VaultError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Seed::try_from(value.as_slice())
    }
}

/// Write as Protobuf bytes
impl TryFrom<Seed> for Vec<u8> {
    type Error = VaultError;

    fn try_from(value: Seed) -> Result<Self, Self::Error> {
        let mut m = proto_Seed::new();
        m.set_id(value.id.to_string());
        match value.source {
            SeedSource::Bytes(s) => {
                m.set_bytes(proto_Encrypted::try_from(&s)?)
            },
            SeedSource::Ledger(s) => {
                m.set_ledger(s.try_into()?)
            }
        }
        m.write_to_bytes()
            .map_err(|e| VaultError::from(e))
    }
}

impl HasUuid for Seed {
    fn get_id(&self) -> Uuid {
        self.id
    }
}
