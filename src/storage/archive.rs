use chrono::{SecondsFormat, Utc};
use fs_extra::{dir, move_items};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct Archive {
    dir: PathBuf,
    archive_type: ArchiveType,
}

pub enum ArchiveType {
    Migrate,
    Delete,
    Update,
    Recover,
    Other,
}

pub const ARCHIVE_DIR: &str = ".archive";

/// Vault archive
impl Archive {
    pub fn create<P>(base: P, archive_type: ArchiveType) -> Archive
    where
        P: AsRef<Path>,
    {
        let dir = PathBuf::from(base.as_ref()).join(ARCHIVE_DIR).join(
            Utc::now()
                // use nanoseconds to avoid reusing archive for consecutive updates
                .to_rfc3339_opts(SecondsFormat::Nanos, true)
                .replace(":", "-"),
        );
        Archive { dir, archive_type }
    }

    fn check_opened(&self) {
        if self.dir.exists() {
            return;
        }
        if fs::create_dir_all(&self.dir.clone()).is_err() {
            error!("Failed to create archive directory");
        }
    }

    /// Close archive by writing a description file with details about archive
    pub fn finalize(&self) {
        let readme = match self.archive_type {
            ArchiveType::Delete => {
                let description = ArchiveDescription {
                    title: "Delete".to_string(),
                    content: vec![DescriptionBlock {
                        title: "DESCRIPTION".to_string(),
                        message: "Files removed from the vault".to_string(),
                    }],
                };
                Some(description)
            }
            ArchiveType::Update => {
                let description = ArchiveDescription {
                    title: "Update".to_string(),
                    content: vec![DescriptionBlock {
                        title: "DESCRIPTION".to_string(),
                        message: "File updated. Save a backup copy of the original data"
                            .to_string(),
                    }],
                };
                Some(description)
            }
            ArchiveType::Recover => {
                let description = ArchiveDescription {
                    title: "Recover corrupted vault".to_string(),
                    content: vec![DescriptionBlock {
                        title: "DESCRIPTION".to_string(),
                        message: "Recover from stale or corrupted data in the vault".to_string(),
                    }],
                };
                Some(description)
            }
            _ => None,
        };
        match readme {
            Some(description) => {
                if self
                    .write("README.txt", description.to_string().as_str())
                    .is_err()
                {
                    warn!("Failed to create README.txt for archive")
                }
            }
            None => {}
        };
    }

    pub fn submit<P>(&self, from: P) -> Result<(), String>
    where
        P: AsRef<Path>,
    {
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
        if path.parent().is_none()
            || path.parent().unwrap() != &self.dir
            || path.file_name().is_none()
            || path.file_name().unwrap().to_str().unwrap() != file_name
        {
            return Err("File should be on the first level".to_string());
        }
        if path.exists() {
            return Err("File already exists".to_string());
        }
        let mut f = match File::create(path) {
            Ok(f) => f,
            Err(e) => return Err(format!("Failed to create file. Error: {}", e.to_string())),
        };
        f.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write to archive. Error: {}", e.to_string()))
    }
}

struct ArchiveDescription {
    title: String,
    content: Vec<DescriptionBlock>,
}

struct DescriptionBlock {
    title: String,
    message: String,
}

impl ToString for DescriptionBlock {
    fn to_string(&self) -> String {
        let mut buf = String::new();
        buf.push_str("== ");
        buf.push_str(self.title.as_str());
        buf.push('\n');
        buf.push('\n');
        buf.push_str(self.message.as_str());

        buf
    }
}

impl ToString for ArchiveDescription {
    fn to_string(&self) -> String {
        let mut buf = String::new();
        buf.push_str("= ");
        buf.push_str(self.title.as_str());
        buf.push('\n');
        buf.push('\n');

        self.content.iter().for_each(|block| {
            buf.push('\n');
            buf.push_str(block.to_string().as_str());
            buf.push('\n');
        });

        buf.trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::archive::{
        Archive, ArchiveDescription, ArchiveType, DescriptionBlock, ARCHIVE_DIR,
    };
    use crate::tests::read_dir_fully;
    use fs_extra::file::write_all;
    use std::fs;
    use std::fs::DirEntry;
    use std::path::{Path, PathBuf};
    use tempdir::TempDir;

    fn read_archives<P: AsRef<Path>>(dir: P) -> Result<Vec<DirEntry>, String> {
        let path = dir.as_ref().to_path_buf();
        let in_arch: Vec<DirEntry> = read_dir_fully(path.join(ARCHIVE_DIR));
        if in_arch.len() != 1 {
            return Err(format!("There're {} elements in archive", in_arch.len()));
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
        write_all(test_file.clone(), "test 1").unwrap();

        assert!(test_file.clone().exists());

        let archive = Archive::create(tmp_dir.path(), ArchiveType::Other);
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
        let archive = Archive::create(tmp_dir.path(), ArchiveType::Other);
        let written = archive.write("README.txt", "Hello\nworld");
        assert_eq!(Ok(()), written);

        let archive_dir = read_archive(&tmp_dir).unwrap();
        let archived_files = read_dir_fully(&archive_dir);
        assert_eq!(1, archived_files.len());
        let content = fs::read_to_string(archive_dir.join("README.txt")).unwrap();
        assert_eq!("Hello\nworld", content);
    }

    #[test]
    fn formats_block() {
        let block = DescriptionBlock {
            title: "Hello World".to_string(),
            message: "TEST 1\ntest 2".to_string(),
        };
        assert_eq!(
            block.to_string(),
            "== Hello World\n".to_owned() + "\n" + "TEST 1\n" + "test 2"
        )
    }

    #[test]
    fn formats_description() {
        let descr = ArchiveDescription {
            title: "Test Archive".to_string(),
            content: vec![
                DescriptionBlock {
                    title: "Description".to_string(),
                    message: "This is a test archive".to_string(),
                },
                DescriptionBlock {
                    title: "Hello World".to_string(),
                    message: "TEST 1\ntest 2".to_string(),
                },
            ],
        };
        assert_eq!(
            descr.to_string(),
            "= Test Archive\n".to_owned()
                + "\n"
                + "\n"
                + "== Description\n"
                + "\n"
                + "This is a test archive\n"
                + "\n"
                + "== Hello World\n"
                + "\n"
                + "TEST 1\n"
                + "test 2"
        )
    }
}
