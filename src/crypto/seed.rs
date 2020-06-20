use crate::{
    mnemonic::Mnemonic,
    structs::{
        crypto::Encrypted,
        seed::{Seed, SeedSource},
    },
};
use uuid::Uuid;
use chrono::Utc;

impl Seed {
    pub fn generate(seed_password: Option<&str>, save_password: &str) -> Result<Seed, ()> {
        let mnemonic = Mnemonic::default();
        let seed = mnemonic.seed(seed_password);
        let result = Seed {
            id: Uuid::new_v4(),
            source: SeedSource::Bytes(Encrypted::encrypt(seed, save_password).map_err(|_| ())?),
            label: None,
            created_at: Utc::now(),
        };
        Ok(result)
    }
}
