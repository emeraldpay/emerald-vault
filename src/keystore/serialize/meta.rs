//! # JSON serialize for meta info field (UTC / JSON)

use keystore::KeyFile;
use keystore::meta::MetaInfo;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};


impl Decodable for MetaInfo {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        d.read_struct("MetaInfo", 0, |_| Ok(MetaInfo))

    }
}

impl Encodable for MetaInfo {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_struct("MetaInfo", 0, |_| Ok(()))
    }
}

impl From<MetaInfo> for KeyFile {
    fn from(meta: MetaInfo) -> Self {
        KeyFile {
            meta: Some(meta),
            ..KeyFile::default()
        }
    }
}

impl From<KeyFile> for MetaInfo {
    fn from(key_file: KeyFile) -> Self {
        key_file.meta.expect("Expect to receive meta info")
    }
}



#[cfg(test)]
mod tests {}
