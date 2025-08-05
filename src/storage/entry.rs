use crate::blockchain::bitcoin::XPub;

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Default)]
pub struct AddEntryOptions {
    pub seed_password: Option<String>,
    pub xpub: Option<XPub>
}


impl AddEntryOptions {
    pub fn with_seed_password(password: &str) -> AddEntryOptions {
        AddEntryOptions {
            seed_password: Some(password.to_string()),
            ..Default::default()
        }
    }
}
