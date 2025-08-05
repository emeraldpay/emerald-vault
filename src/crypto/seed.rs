use crate::structs::seed::Seed;

#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use uuid::Uuid;

impl Seed {
    #[cfg(test)]
    pub fn test_generate(
        seed_password: Option<String>,
        global_password: &[u8],
        global: Option<crate::structs::crypto::GlobalKey>,
    ) -> Result<Seed, ()> {
        use crate::{
            mnemonic::Mnemonic,
            structs::{
                crypto::Encrypted,
                seed::SeedSource,
            },
        };

        let mnemonic = Mnemonic::default();
        let seed = mnemonic.seed(seed_password);
        let result = Seed {
            id: Uuid::new_v4(),
            source: SeedSource::Bytes(Encrypted::encrypt(seed, global_password, global).map_err(|_| ())?),
            label: None,
            created_at: Utc::now(),
        };
        Ok(result)
    }
}
