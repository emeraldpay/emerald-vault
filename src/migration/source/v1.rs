use std::fs::{read_dir, File};
use uuid::Uuid;
use std::path::PathBuf;
use crate::migration::source::json_data::KeyFileV2;
use std::io::Read;

struct V1Storage {
    /// Parent directory for storage
    base_path: PathBuf,
}

struct Source {
    path: PathBuf,
    kf: KeyFileV2
}

