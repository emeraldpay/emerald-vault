use std::fs;
use std::fs::File;
use std::path::PathBuf;
use png::Limits;
use protobuf::Message;
use uuid::Uuid;
use crate::convert::error::ConversionError;
use crate::error::VaultError;
use crate::storage::files::try_vault_file;

const PNG_SUFFIX: &str = "png";
const SIZE_LIMIT: usize = 1 * 1024 * 1024;

pub struct Icons {
    pub(crate) dir: PathBuf,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Icon {
    id: Uuid,
    entity_type: EntityType,
    image_type: ImageType,
}

#[derive(Clone, PartialEq, Eq, Debug)]
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
                    match try_vault_file(&path, PNG_SUFFIX) {
                        Ok(id) => {
                            if let Some(t) = self.find_entity_type(id) {
                                let icon = Icon::from((id, t));
                                result.push(icon)
                            }
                        }
                        Err(_) => {}
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
    /// Make simple checks that the image can be actually used.
    ///
    /// In short:
    /// - it should be an image in PNG format
    /// - square size (i.e., with equal to height)
    /// - not too small, must not be smaller than 32px
    /// - not too large, must not be larger that 1024px
    fn validate_image(img: &Vec<u8>) -> Result<(), ConversionError> {
        if img.len() == 0 || img.len() > SIZE_LIMIT {
            return Err(ConversionError::InvalidLength)
        }
        let decoder = png::Decoder::new_with_limits(img.as_slice(), Limits { bytes: SIZE_LIMIT });
        let reader = decoder.read_info()
            .map_err(|_| ConversionError::UnsupportedFormat)?;
        let info = reader.info();
        if info.width != info.height || info.width < 32 || info.width > 1024 {
            return Err(ConversionError::UnsupportedFormat)
        }
        Ok(())
    }

    ///
    /// Update the icon in the vault. Creates new if not exists, or updates with new images.
    /// If a `None` image is specified then it deletes the current icon if it exists.
    pub fn update(&self, id: Uuid, image: Option<Vec<u8>>) -> Result<(), VaultError> {
        let path = self.dir.join(format!("{}.{}", id, PNG_SUFFIX));
        match image {
            Some(image) => {
                let _ = Icons::validate_image(&image)?;
                if let Some(_) = self.find_entity_type(id) {
                    fs::write(path, image)
                        .map_err(|_| VaultError::FilesystemError("IO Error".to_string()))
                } else {
                    Err(VaultError::IncorrectIdError)
                }
            },
            None => {
                if path.is_file() {
                    let _ = fs::remove_file(path)?;
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
    use crate::storage::icons::EntityType;
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
        seed.created_at = Utc.timestamp_millis(0);
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

        assert_eq!(current.get(0).unwrap().id, id);
        assert_eq!(current.get(0).unwrap().entity_type, EntityType::SEED);

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

        assert_eq!(current.get(0).unwrap().id, wallet_id);
        assert_eq!(current.get(0).unwrap().entity_type, EntityType::WALLET);

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
}
