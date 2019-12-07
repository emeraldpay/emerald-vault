use std::path::{PathBuf, Path};
use std::fs;
use fs_extra::{
    dir,
    move_items,
    file::write_all
};
use chrono::Utc;

pub struct Archive {
    dir: PathBuf
}

/// Vault archive
impl Archive {
    pub fn create<P>(base: P) -> Archive where P: AsRef<Path> {
        let dir = PathBuf::from(base.as_ref())
            .join("archive")
            .join(Utc::now().to_rfc3339());
        Archive {
            dir
        }
    }

    fn check_opened(&self) {
        if self.dir.exists() {
            return;
        }
        fs::create_dir_all(&self.dir.clone());
    }

    pub fn submit<P>(&self, from: P) -> Result<(), String> where P: AsRef<Path> {
        self.check_opened();
        let options = dir::CopyOptions::new();
        let mut from_vec = Vec::new();
        from_vec.push(from);
        move_items(&from_vec, self.dir.clone(), &options)
            .map(|_| ())
            .map_err(|e| format!("Failed to copy to archive. Error: {}", e.to_string()))
    }

    pub fn write(&self, file_name: &str, content: &str) -> Result<(), String> {
        self.check_opened();
        let path = &self.dir.join(file_name);
        if path.parent().is_none() || path.parent().unwrap() != &self.dir
            || path.file_name().is_none() || path.file_name().unwrap().to_str().unwrap() != file_name {
            return Err("File should be on the first level".to_string());
        }
        if path.exists() {
            return Err("File already exists".to_string());
        }
        write_all(path, content)
            .map(|_| ())
            .map_err(|e| format!("Failed to add to archive. Error: {}", e.to_string()))
    }
}
