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
        if fs::create_dir_all(&self.dir.clone()).is_err() {
            error!("Failed to create archive directory");
        }
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

#[cfg(test)]
mod tests {
    use tempdir::TempDir;
    use crate::storage::archive::Archive;
    use std::fs;
    use std::fs::DirEntry;

    #[test]
    pub fn writes_readme() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let archive = Archive::create(tmp_dir.path());
        let written = archive.write("README.txt", "Hello\nworld");
        assert!(written.is_ok());
        let mut in_arch: Vec<DirEntry> = fs::read_dir(tmp_dir.into_path().join("archive"))
            .unwrap()
            .map(|i| i.unwrap())
            .collect();
        assert_eq!(1, in_arch.len());
        let elem = &in_arch[0];
        let mut act_archive = fs::read_dir(elem.path()).unwrap();
        assert_eq!(1, act_archive.count());
        let content = fs::read_to_string(elem.path().join("README.txt")).unwrap();
        assert_eq!("Hello\nworld", content);
    }
}
