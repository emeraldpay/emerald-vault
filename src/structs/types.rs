use uuid::Uuid;

/// Interface to an identifiable entiry, i.e. that stored on can be stored in the Vault as an individual object
pub trait HasUuid {
    /// Return current id
    fn get_id(&self) -> Uuid;
}

pub trait IsVerified {
    fn verify(self) -> Result<Self, String>
    where
        Self: std::marker::Sized;
}
