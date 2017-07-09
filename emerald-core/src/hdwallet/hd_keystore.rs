use super::Error;

/// Keyfile for HD Wallet
#[derive(Clone, Debug, Eq)]
pub struct HDWallet_Keyfile {
    /// Specifies if `Keyfile` is visible
    pub visible: Option<bool>,

    /// User specified name
    pub name: Option<String>,

    /// User specified description
    pub description: Option<String>,

    /// Address
    pub address: Address,

    /// UUID v4
    pub uuid: Uuid,

    /// Cipher type
    pub cipher: String,

    ///
    pub hardware: HDWallet_Type,

    ///
    pub hd_path: String,

}

// TODO:
// add serialization stuff