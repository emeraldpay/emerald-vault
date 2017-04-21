//! # JSON serialize for meta info field (UTC / JSON)

use super::crypto::decode_str;
use keystore::KeyFile;
use keystore::meta::MetaInfo;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};


impl Decodable for MetaInfo {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        d.read_struct("MetaInfo", 1, |d| {
            let data = (d.read_struct_field("data", 0, |d| decode_str(d)))?;

            Ok(MetaInfo { data: data })
        })

    }
}

impl Encodable for MetaInfo {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_struct("MetaInfo", 6, |s| {
            (s.emit_struct_field("data", 0, |s| s.emit_str(&self.data)))?;

            Ok(())
        })
    }
}

impl From<MetaInfo> for KeyFile {
    fn from(meta: MetaInfo) -> Self {
        KeyFile {
            meta: Some(meta.data),
            ..KeyFile::default()
        }
    }
}

impl From<KeyFile> for MetaInfo {
    fn from(key_file: KeyFile) -> Self {
        MetaInfo { data: key_file.meta.expect("Expect to receive meta info") }
    }
}



#[cfg(test)]
mod tests {}
