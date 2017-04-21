//! # JSON serialize for meta info field (UTC / JSON)

use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaInfo {
    ///
    pub data: String,
}
