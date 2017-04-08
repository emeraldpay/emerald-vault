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

#[cfg(target_os="macos")]
static DEFAULT_PATH: &str = "~/Library/Emerald";
#[cfg(target_os="linux")]
static DEFAULT_PATH: &str = "~/.emerald";
#[cfg(target_os="windows")]
static DEFAULT_PATH: &str = "%USERDIR%\\.emerald";

impl<'a> Storages<'a> {
    /// Create storage using user directory if specified,
    /// or default path in other case.
    pub fn new(path: Option<&'a Path>) -> Storages<'a> {
        match path {
            Some(p) => Storages { base_dir: p },
            _ => Storages { base_dir: Path::new(DEFAULT_PATH) },
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn should_use_default_path() {
        let st = Storages::new(None);
        assert_eq!(st.base_dir.as_os_str(), Path::new(DEFAULT_PATH).as_os_str());
    }

    #[test]
    fn should_use_user_path() {
        let user_path = Path::new("../some/path");
        let st = Storages::new(Some(&user_path));

        assert_eq!(st.base_dir.as_os_str(), user_path.as_os_str());
    }
}
