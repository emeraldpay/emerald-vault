//! # Logic to manage configuration parameters
pub enum SEC_LEVEL {
    Normal,
    High,
    Ultra
}

/// Сonfiguration parameters
pub struct Config {
    pub security_level: SEC_LEVEL,
}

impl Config {
    pub fn new() -> Config {
        Config {
            security_level: SEC_LEVEL::Normal
        }
    }
}
