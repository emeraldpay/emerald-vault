use std::path::{PathBuf, Path};
use std::fs;
use fs_extra::{
    dir,
    move_items,
    file::write_all
};
use chrono::{Utc, SecondsFormat};
use std::fs::File;
use std::io::Write;

pub struct Archive {
    dir: PathBuf
}

/// Vault archive
impl Archive {
    pub fn create<P>(base: P) -> Archive where P: AsRef<Path> {
        let dir = PathBuf::from(base.as_ref())
            .join("archive")
            .join(
                Utc::now()
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .replace(":", "-")
            );
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
        let mut f = match File::create(path) {
            Ok(f) => f,
            Err(e) => return Err(format!("Failed to create file. Error: {}", e.to_string()))
        };
        f.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write to archive. Error: {}", e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;
    use crate::storage::archive::Archive;
    use std::fs;
    use std::fs::DirEntry;
    use std::path::{PathBuf, Path};

    fn read_dir_fully<P: AsRef<Path>>(path: P) -> Vec<DirEntry> {
        fs::read_dir(path)
            .unwrap()
            .map(|i| i.unwrap())
            .collect()
    }

    fn read_archives<P: AsRef<Path>>(dir: P) -> Result<Vec<DirEntry>, String> {
        let path = dir.as_ref().to_path_buf();
        let mut in_arch: Vec<DirEntry> = read_dir_fully(path.join("archive"));
        if in_arch.len() != 1 {
            return Err(format!("There're {} elements in archive", in_arch.len()))
        }
        Ok(in_arch)
    }

    fn read_archive<P: AsRef<Path>>(dir: P) -> Result<PathBuf, String> {
        let all = read_archives(dir)?;
        Ok(all.first().unwrap().path())
    }

    #[test]
    pub fn add_existing_file() {
        let tmp_dir = TempDir::new("emerald-archive-test").expect("Dir not created");
        let test_file = tmp_dir.path().join("test.txt");
        fs_extra::file::write_all(test_file.clone(), "test 1").unwrap();

        assert!(test_file.clone().exists());

        let archive = Archive::create(tmp_dir.path());
        let result = archive.submit(test_file.clone());
        assert_eq!(Ok(()), result);
        assert!(!test_file.exists());

        let archive_dir = read_archive(&tmp_dir).unwrap();
        let archived_files = read_dir_fully(&archive_dir);
        assert_eq!(1, archived_files.len());
        assert_eq!("test.txt", archived_files[0].file_name());
        let content = fs::read_to_string(archive_dir.join("test.txt")).unwrap();
        assert_eq!("test 1", content);
    }

    #[test]
    pub fn writes_readme() {
        let tmp_dir = TempDir::new("emerald-archive-test").expect("Dir not created");
        let archive = Archive::create(tmp_dir.path());
        let written = archive.write("README.txt", "Hello\nworld");
        assert_eq!(Ok(()), written);

        let archive_dir = read_archive(&tmp_dir).unwrap();
        let archived_files = read_dir_fully(&archive_dir);
        assert_eq!(1, archived_files.len());
        let content = fs::read_to_string(archive_dir.join("README.txt")).unwrap();
        assert_eq!("Hello\nworld", content);
    }
}
