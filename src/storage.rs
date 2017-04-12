//! # Chain-related storage

use log::LogLevel;
use std::env;
use std::fs;
use std::io::Error;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
static DEFAULT_PATH: &'static str = "~/.emerald";
#[cfg(target_os = "macos")]
static DEFAULT_PATH: &'static str = "~/Library/Emerald";
#[cfg(target_os = "windows")]
static DEFAULT_PATH: &'static str = "%APPDATA%\\.emerald";

/// Base dir for internal data, all chain-related should be store in subdirectories
#[derive(Debug, Clone)]
pub struct Storages {
    /// base dir
    base_dir: PathBuf,
}

#[cfg(all(unix, not(target_os = "macos"), not(target_os = "ios"), not(target_os = "android")))]
pub fn default_path() -> PathBuf {
    let mut config_dir = env::home_dir().expect("Expect path to home dir");
    config_dir.push(".emerald");
    config_dir
}

#[cfg(target_os = "macos")]
pub fn default_path() -> PathBuf {
    let mut config_dir = env::home_dir().expect("Expect path to home dir");
    config_dir.push("Library");
    config_dir.push("Emerald");
    config_dir
}

#[cfg(target_os = "windows")]
pub fn default_path() -> PathBuf {
    let mut config_dir = env::var("APPDATA").expect("Expect 'APPDATA' environment variable");
    config_dir.push(".emerald");
    config_dir
}

impl Storages {
    /// Create storage using user directory if specified,
    /// or default path in other case.
    pub fn new(path: PathBuf) -> Storages {
        Storages { base_dir: path }
    }

    pub fn init(&self) -> Result<(), Error> {
        if !&self.base_dir.exists() {
            if log_enabled!(LogLevel::Info) {
                info!("Init new storage at {}", self.base_dir.display());
            }
            fs::create_dir(self.base_dir.as_path())?
        }
        Ok(())
    }
}

impl Default for Storages {
    fn default() -> Self {
        Storages { base_dir: default_path() }
    }
}

/// Subdir for a chain
#[derive(Debug, Clone)]
pub struct ChainStorage<'a> {
    /// subdir name
    id: String,
    /// storage
    base: &'a Storages,
}

impl<'a> ChainStorage<'a> {
    pub fn new(base: &'a Storages, id: String) -> ChainStorage<'a> {
        ChainStorage { id: id, base: base }
    }

    pub fn init(&self) -> Result<(), Error> {
        let mut p: PathBuf = self.base.base_dir.to_path_buf();
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn should_use_default_path() {
        let st = Storages::default();
        assert_eq!(st.base_dir, default_path());
    }

    #[test]
    fn should_use_user_path() {
        let user_path: &str = "/tmp/some";
        let st = Storages::new(PathBuf::from(user_path));

        assert_eq!(st.base_dir, PathBuf::from(user_path));
    }
}
