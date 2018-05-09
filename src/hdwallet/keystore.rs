use super::Error;
use keystore::{CryptoType, KeyFile};

/// `Keyfile` for HD Wallet
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct HdwalletCrypto {
    /// Cipher type 'hardware'
    pub cipher: String,

    /// HD Wallet type
    pub hardware: String,

    /// HD path as specified in BIP-32
    pub hd_path: String,
}

impl Default for HdwalletCrypto {
    fn default() -> HdwalletCrypto {
        HdwalletCrypto {
            cipher: String::new(),
            hardware: String::new(),
            hd_path: String::new(),
        }
    }
}

impl HdwalletCrypto {
    /// Try to convert from `Keyfile`
    /// Fail if type of `crypto` section than `Self`
    ///
    pub fn try_from(kf: &KeyFile) -> Result<Self, Error> {
        match kf.crypto {
            CryptoType::HdWallet(ref hd) => Ok(Self {
                cipher: hd.cipher.clone(),
                hardware: hd.hardware.clone(),
                hd_path: hd.hd_path.clone(),
            }),
            _ => Err(Error::HDWalletError("HD wallet".to_string())),
        }
    }
}

impl Into<KeyFile> for HdwalletCrypto {
    fn into(self) -> KeyFile {
        KeyFile {
            crypto: CryptoType::HdWallet(self),
            ..Default::default()
        }
    }
}

//impl Decodable for HdwalletCrypto {
//    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
//        d.read_struct("Crypto", 3, |d| {
//            let cipher = d.read_struct_field("cipher", 0, |d| decode_str(d))?;
//            let hardware = d.read_struct_field("hardware", 1, |d| decode_str(d))?;
//            let hd_path = d.read_struct_field("hd_path", 2, |d| decode_str(d))?;
//
//            Ok(Self {
//                cipher,
//                hardware,
//                hd_path,
//            })
//        })
//    }
//}

//impl Encodable for HdwalletCrypto {
//    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
//        s.emit_struct("Crypto", 3, |s| {
//            s.emit_struct_field("cipher", 0, |s| s.emit_str(&self.cipher.to_string()))?;
//            s.emit_struct_field("hardware", 1, |s| self.hardware.encode(s))?;
//            s.emit_struct_field("hd_path", 2, |s| self.hd_path.encode(s))?;
//
//            Ok(())
//        })
//    }
//}
