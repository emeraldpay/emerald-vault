use std::str::FromStr;
use emerald_hwkey::ledger::app::BitcoinApp;
use emerald_hwkey::ledger::app::EthereumApp;
use emerald_hwkey::ledger::connect::LedgerKeyShared;
use emerald_hwkey::ledger::app::PubkeyAddressApp;
use hdpath::{HDPath, StandardHDPath};
use hmac::digest::Digest;
use hmac::Hmac;
use hmac::Mac;
use sha2::Sha256;
use emerald_hwkey::ledger::connect::LedgerKey;
use crate::error::VaultError;
use crate::structs::seed::{Bytes256, FingerprintType, HDPathFingerprint, LedgerSource};

///
/// Fingerprints per hardware key
pub trait Fingerprints {
    ///
    /// Find currently available fingerprints on the device.
    ///
    /// Note that the response may contain only part of the fingerprints and change depending on availability.
    /// For example, with Ledger, it depends on the application which is currently open. Because we can only get a fingerprint specific to the current app.
    /// So it supposed to be called periodically to get all fingerprints and compare with stored fingerprint if they intersect
    ///
    fn find_fingerprints(&self) -> Result<Vec<HDPathFingerprint>, VaultError>;
}



fn read(app: &dyn PubkeyAddressApp, hd_path: StandardHDPath) -> Option<(StandardHDPath, [u8; 33])> {
    if let Ok(key) = app.get_extkey_at(&hd_path) {
        let pub_key = key.as_pubkey();
        let pub_key = pub_key.serialize();
        Some((hd_path, pub_key))
    } else {
        None
    }
}

///
/// The input is supposed to be a pair of Hd Path and Public Key encoded as a
///
/// Calculated a fingerprint as `HMAC_SHA256` where key is `emerald-seed-fingerprint/pubkey-hmac-sha256` and the message
/// is `HD_PATH_BYTES | PUBKEY_BYTES`
impl TryFrom<(StandardHDPath, [u8; 33])> for HDPathFingerprint {
    type Error = ();

    fn try_from(value: (StandardHDPath, [u8; 33])) -> Result<Self, Self::Error> {
        let mut hmac = Hmac::<Sha256>::new_from_slice(b"emerald-seed-fingerprint/pubkey-hmac-sha256").unwrap();
        hmac.update(value.0.to_bytes().as_slice());
        hmac.update(value.1.as_slice());
        let result = hmac.finalize();
        let hash = result.into_bytes();
        let hash = Bytes256::try_from(hash.as_slice()).map_err(|_| ())?;

        Ok(HDPathFingerprint {
            value: FingerprintType::PubkeySha256(hash),
        })
    }
}

impl Fingerprints for LedgerSource {
    fn find_fingerprints(&self) -> Result<Vec<HDPathFingerprint>, VaultError> {
        // DO NOT LOCK LEDGER HERE. Because it's usually called from a context which already has a lock.
        // So the method spec tells the called to ensure an exclusive access
        let manager = LedgerKeyShared::instance().map_err(|_| VaultError::PrivateKeyUnavailable)?;
        manager.find_fingerprints()
    }
}

impl<LK: LedgerKey + 'static> Fingerprints for LedgerKeyShared<LK> {

    fn find_fingerprints(&self) -> Result<Vec<HDPathFingerprint>, VaultError> {
        // on Ledger, it uses m/44'/COIN'/0'/0/0.
        // Initially we tried to use m/44'/COIN'/128'/0/0,
        // but it's not easily accessible from the Ledger with latest firmware/app because it's a non-standard path
        let mut source = vec![];
        let app = self.get_app_details()?.name;
        if app.starts_with("Ethereum") {
            let app = self.access::<EthereumApp>()?;
            if let Some(fp) = read(&app, StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap()) {
                source.push(fp)
            }
            if let Some(fp) = read(&app, StandardHDPath::from_str("m/44'/61'/0'/0/0").unwrap()) {
                source.push(fp)
            }
        } else if app.starts_with("Bitcoin") {
            let app = self.access::<BitcoinApp>()?;
            if let Some(fp) = read(&app, StandardHDPath::from_str("m/44'/0'/0'/0/0").unwrap()) {
                source.push(fp)
            }
            if let Some(fp) = read(&app, StandardHDPath::from_str("m/44'/1'/0'/0/0").unwrap()) {
                source.push(fp)
            }
        } else {
            return Ok(vec![])
        }

        let mut result = vec![];
        for s in source {
            if let Ok(fp) = HDPathFingerprint::try_from(s) {
                result.push(fp)
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use hdpath::StandardHDPath;
    use crate::structs::seed::HDPathFingerprint;

    #[test]
    fn create_zero() {
        let pk = (StandardHDPath::from_str("m/44'/60'/0'/0/0").unwrap(), [0u8; 33]);
        let fingerprint = HDPathFingerprint::try_from(pk);
        assert!(fingerprint.is_ok());
        let fingerprint = fingerprint.unwrap();
        assert_eq!(hex::encode(fingerprint.value.to_vec()), "8641f4987cdf650bc82a8f97596de5c9457c327662452cba2a1afe552e2ff170")
    }

}
