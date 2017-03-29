#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

use log::LogLevel;
use std::fs;
use std::io::Error;
use std::path::{Path, PathBuf};

/// Base dir for internal data, all chain-related should be store in subdirectories
#[derive(Debug, Clone)]
pub struct Storages<'a> {
    /// base dir
    base_dir: &'a Path,
}

impl<'a> Storages<'a> {
    /// Create storage using default directory
    pub fn new() -> Storages<'a> {
        Storages {
            //TODO use user home subdir
            base_dir: &Path::new("emerald_data"),
        }
    }

    pub fn init(&self) -> Result<(), Error> {
        if !&self.base_dir.exists() {
            if log_enabled!(LogLevel::Info) {
                info!("Init new storage at {}", self.base_dir.display());
            }
            fs::create_dir(self.base_dir)?
        }
        Ok(())
    }
}

/// Subdir for a chain
#[derive(Debug, Clone)]
pub struct ChainStorage<'a> {
    /// subdir name
    id: String,
    /// storage
    base: &'a Storages<'a>,
}

impl<'a> ChainStorage<'a> {
    pub fn new(base: &'a Storages, id: String) -> ChainStorage<'a> {
        ChainStorage { id: id, base: base }
    }
    pub fn init(&self) -> Result<(), Error> {
        let mut p: PathBuf = self.base.base_dir.to_path_buf().clone();
        p.push(self.id.clone());
        if !p.exists() {
            if log_enabled!(LogLevel::Info) {
                info!("Init new chain at {}", p.display());
            }
            fs::create_dir(p)?
        }
        Ok(())
    }

    pub fn get_path(&self, id: String) -> Result<PathBuf, Error> {
        let mut p: PathBuf = self.base.base_dir.to_path_buf().clone();
        p.push(self.id.clone());
        p.push(id.clone());
        if !p.exists() {
            if log_enabled!(LogLevel::Debug) {
                debug!("Init new chain storage at {}", p.display());
            }
            fs::create_dir(&p)?
        }
        Ok(p)
    }
}
