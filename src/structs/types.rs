use uuid::Uuid;

pub trait HasUuid {
    fn get_id(&self) -> Uuid;
}

pub trait IsVerified {
    fn verify(self) -> Result<Self, String>
        where Self: std::marker::Sized;
}
