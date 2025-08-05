use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use crate::convert::error::ConversionError;
use crate::error::VaultError;
use crate::storage::files::try_vault_file;
use std::fmt::Display;
use std::io::Cursor;
use image::{ImageFormat};
use image::imageops::FilterType;
use image::ImageReader;

const PNG_SUFFIX: &str = "png";
const SIZE_LIMIT: usize = 1024 * 1024;

pub struct Icons {
    pub(crate) dir: PathBuf,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Icon {
    pub id: Uuid,
    pub entity_type: EntityType,
    pub image_type: ImageType,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
pub enum EntityType {
    WALLET,
    SEED
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ImageType {
    PNG
}

impl From<(Uuid, EntityType)> for Icon {

    fn from(value: (Uuid, EntityType)) -> Self {
        Icon {
            id: value.0,
            entity_type: value.1,
            image_type: ImageType::PNG
        }
    }
}

impl Icons {

    ///
    /// Check if a Vault entry with that id exists
    fn try_entity(&self, id: Uuid, suffix: &str) -> bool {
        self.dir.join(format!("{}.{}", id, suffix)).is_file()
    }

    ///
    /// Find an entry for the icon by checking which files exist with the same id
    fn find_entity_type(&self, id: Uuid) -> Option<EntityType> {
        if self.try_entity(id, "wallet") {
            return Some(EntityType::WALLET)
        }
        if self.try_entity(id, "seed") {
            return Some(EntityType::SEED)
        }
        None
    }

    ///
    /// List all current icons in the vault
    pub fn list(&self) -> Result<Vec<Icon>, VaultError> {
        let mut result = Vec::new();
        if self.dir.is_dir() {
            for entry in fs::read_dir(&self.dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    if let Ok(id) = try_vault_file(&path, PNG_SUFFIX) {
                        if let Some(t) = self.find_entity_type(id) {
                            let icon = Icon::from((id, t));
                            result.push(icon)
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    ///
    /// Read image for the specified icon
    pub fn get_image(&self, id: Uuid) -> Result<Vec<u8>, VaultError> {
        let path = self.dir.join(format!("{}.{}", id, PNG_SUFFIX));
        fs::read(path)
            .map_err(|_| VaultError::FilesystemError("Failed to read image".to_string()))
    }

    ///
    /// Tries to convert the image to a supported format:
    /// - convert to PNG
    /// - resize down to 1024px if larger
    /// - return error if size is less than 32px
    /// - cut sides to make it square
    fn preprocess_image(img: Vec<u8>) -> Result<Vec<u8>, ConversionError> {
        if img.is_empty() || img.len() > SIZE_LIMIT {
            return Err(ConversionError::InvalidLength)
        }

        let reader = ImageReader::new(Cursor::new(&img))
            .with_guessed_format()
            .expect("Cursor io never fails");
        let format = reader.format()
            .ok_or(ConversionError::UnsupportedFormat)?;
        let change_format = match format {
            ImageFormat::Jpeg => true,
            ImageFormat::Png => false,
            _ => return Err(ConversionError::UnsupportedFormat)
        };
        let decoded = reader.decode()
            .map_err(|_| ConversionError::UnsupportedFormat)?;

        if decoded.height() < 32 || decoded.width() < 32 {
            return Err(ConversionError::UnsupportedFormat)
        }

        let downsize = decoded.height() > 1024 || decoded.width() > 1024;
        let is_square = decoded.height() == decoded.width();

        if !change_format && !downsize && is_square {
            return Ok(img)
        }

        let square = if !is_square {
            let cut = Icons::cut_square(decoded.width(), decoded.height());
            decoded.crop_imm(cut.0, cut.1, cut.2, cut.3)
        } else {
            decoded
        };

        let right_size = if square.width() > 1024 {
            square.resize(1024, 1024, FilterType::Triangle)
        } else {
            square
        };

        let mut target = Cursor::new(vec![]);
        right_size.write_to(&mut target, ImageFormat::Png)
            .map_err(|_| ConversionError::UnsupportedFormat)?;

        Ok(target.into_inner())
    }

    fn cut_square(width: u32, height: u32) -> (u32, u32, u32, u32) {
        if width > height {
            let xmargin = (width - height) / 2;
            let size = height;
            (xmargin, 0, size, size)
        } else {
            let ymargin = (height - width) / 2;
            let size = width;
            (0, ymargin, size, size)
        }
    }

    ///
    /// Update the icon in the vault. Creates new if not exists, or updates with new images.
    /// If a `None` image is specified then it deletes the current icon if it exists.
    pub fn update(&self, id: Uuid, image: Option<Vec<u8>>) -> Result<(), VaultError> {
        let path = self.dir.join(format!("{}.{}", id, PNG_SUFFIX));
        match image {
            Some(image) => {
                let image = Icons::preprocess_image(image)?;
                if self.find_entity_type(id).is_some() {
                    fs::write(path, image)
                        .map_err(|_| VaultError::FilesystemError("IO Error".to_string()))
                } else {
                    Err(VaultError::IncorrectIdError)
                }
            },
            None => {
                if path.is_file() {
                    fs::remove_file(path)?;
                }
                Ok(())
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use chrono::{TimeZone, Utc};
    use tempdir::TempDir;
    use crate::storage::icons::{EntityType, Icons};
    use crate::storage::vault::VaultStorage;
    use crate::structs::seed::Seed;
    use crate::structs::types::HasUuid;
    use crate::structs::wallet::Wallet;

    #[test]
    fn add_icon_for_seed() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let all = vault.seeds().list().unwrap();
        assert_eq!(0, all.len());

        let mut seed = Seed::test_generate(None, "testtest".as_bytes(), None).unwrap();
        seed.created_at = Utc.timestamp_millis_opt(0).unwrap();
        let id = seed.get_id();
        vault.seeds().add(seed.clone()).unwrap();


        let icons = vault.icons();
        let initial = icons.list().unwrap();
        assert_eq!(initial.len(), 0);

        let image = fs::read(PathBuf::from("tests/emerald_icon.png")).unwrap();

        let updated = icons.update(id, Some(image.clone()));
        assert!(updated.is_ok());

        let current = icons.list().unwrap();
        assert_eq!(current.len(), 1);

        assert_eq!(current.first().unwrap().id, id);
        assert_eq!(current.first().unwrap().entity_type, EntityType::SEED);

        let image_stored = icons.get_image(id).unwrap();

        assert_eq!(image_stored, image);
    }

    #[test]
    fn add_icon_for_wallet() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let all = vault.seeds().list().unwrap();
        assert_eq!(0, all.len());

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets().add(wallet).unwrap();

        let icons = vault.icons();
        let initial = icons.list().unwrap();
        assert_eq!(initial.len(), 0);

        let image = fs::read(PathBuf::from("tests/emerald_icon.png")).unwrap();

        let updated = icons.update(wallet_id, Some(image.clone()));
        assert!(updated.is_ok());

        let current = icons.list().unwrap();
        assert_eq!(current.len(), 1);

        assert_eq!(current.first().unwrap().id, wallet_id);
        assert_eq!(current.first().unwrap().entity_type, EntityType::WALLET);

        let image_stored = icons.get_image(wallet_id).unwrap();

        assert_eq!(image_stored, image);
    }

    #[test]
    fn delete_icon() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let all = vault.seeds().list().unwrap();
        assert_eq!(0, all.len());

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets().add(wallet).unwrap();

        let icons = vault.icons();
        let image = fs::read(PathBuf::from("tests/emerald_icon.png")).unwrap();
        let updated = icons.update(wallet_id, Some(image.clone()));
        assert!(updated.is_ok());

        let current = icons.list().unwrap();
        assert_eq!(current.len(), 1);

        let deleted = icons.update(wallet_id, None);
        assert!(deleted.is_ok());

        let current = icons.list().unwrap();
        assert_eq!(current.len(), 0);
    }

    #[test]
    fn reject_broken_png() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let all = vault.seeds().list().unwrap();
        assert_eq!(0, all.len());

        let wallet = Wallet {
            ..Wallet::default()
        };
        let wallet_id = vault.wallets().add(wallet).unwrap();

        let icons = vault.icons();
        let initial = icons.list().unwrap();
        assert_eq!(initial.len(), 0);

        let image = vec![0, 1, 2, 3, 4];

        let updated = icons.update(wallet_id, Some(image.clone()));
        assert!(updated.is_err());
    }

    #[test]
    fn cut_to_size() {
        assert_eq!(Icons::cut_square(100,  50), (25, 0, 50, 50));
        assert_eq!(Icons::cut_square(50,  100), (0, 25, 50, 50));
        assert_eq!(Icons::cut_square(100, 100), (0, 0, 100, 100));
        assert_eq!(Icons::cut_square(70,  100), (0, 15, 70, 70));

        assert_eq!(Icons::cut_square(101,  50), (25, 0, 50, 50));

        assert_eq!(Icons::cut_square(101,  100), (0, 0, 100, 100));
        assert_eq!(Icons::cut_square(102,  100), (1, 0, 100, 100));
        assert_eq!(Icons::cut_square(103,  100), (1, 0, 100, 100));
        assert_eq!(Icons::cut_square(104,  100), (2, 0, 100, 100));

        assert_eq!(Icons::cut_square(102,  101), (0, 0, 101, 101));
        assert_eq!(Icons::cut_square(102,  103), (0, 0, 102, 102));
        assert_eq!(Icons::cut_square(102,  104), (0, 1, 102, 102));
    }

    #[test]
    fn add_icon_as_jpeg() {
        let tmp_dir = TempDir::new("emerald-vault-test").expect("Dir not created");
        let vault = VaultStorage::create(tmp_dir.path()).unwrap();

        let all = vault.seeds().list().unwrap();
        assert_eq!(0, all.len());

        let mut seed = Seed::test_generate(None, "testtest".as_bytes(), None).unwrap();
        seed.created_at = Utc.timestamp_millis_opt(0).unwrap();
        let id = seed.get_id();
        vault.seeds().add(seed.clone()).unwrap();

        let icons = vault.icons();

        let image = fs::read(PathBuf::from("tests/emerald_icon.jpeg")).unwrap();

        let updated = icons.update(id, Some(image.clone()));
        assert!(updated.is_ok());

        let current = icons.list().unwrap();
        assert_eq!(current.len(), 1);
        let image_stored = icons.get_image(id).unwrap();

        assert!(image_stored.len() > 1_000);
    }
}
