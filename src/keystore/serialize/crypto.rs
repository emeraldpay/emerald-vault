//! # JSON serialize for crypto field (UTC / JSON)

use super::util::KECCAK256_BYTES;
use super::{Cipher, CryptoType, Error, Kdf, KeyFile, CIPHER_IV_BYTES, KDF_SALT_BYTES};
use hex::{FromHex, ToHex};
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::default::Default;
use std::str::FromStr;

/// Derived core length in bytes (by default)
pub const DEFAULT_DK_LENGTH: usize = 32;

byte_array_struct!(Salt, KDF_SALT_BYTES);
byte_array_struct!(Mac, KECCAK256_BYTES);
byte_array_struct!(Iv, CIPHER_IV_BYTES);

///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreCrypto {
    /// Cipher
    pub cipher: Cipher,

    /// Cipher text
    pub cipher_text: Vec<u8>,

    /// Params for `Cipher`
    pub cipher_params: CipherParams,

    /// Key derivation funciton
    pub kdf: Kdf,

    /// `Kdf` length for parameters
    pub kdfparams_dklen: usize,

    /// Cryptographic salt for `Kdf`
    pub kdfparams_salt: Salt,

    /// HMAC authentication code
    pub mac: Mac,
}

#[derive(Clone, Debug, PartialEq, Eq, RustcDecodable, RustcEncodable)]
pub struct CipherParams {
    pub iv: Iv,
}

impl Default for CipherParams {
    fn default() -> Self {
        CipherParams {
            iv: Iv::from([0; CIPHER_IV_BYTES]),
        }
    }
}

impl CoreCrypto {
    ///
    pub fn try_from(kf: &KeyFile) -> Result<Self, Error> {
        match kf.crypto {
            CryptoType::Core(ref core) => Ok(CoreCrypto {
                cipher: core.cipher,
                cipher_text: core.cipher_text.clone(),
                cipher_params: core.cipher_params.clone(),
                kdf: core.kdf,
                kdfparams_dklen: core.kdfparams_dklen,
                kdfparams_salt: Salt::from(core.kdfparams_salt.0),
                mac: Mac::from(core.mac.0),
            }),
            _ => Err(Error::NotFound),
        }
    }
}

impl Default for CoreCrypto {
    fn default() -> Self {
        Self {
            cipher: Cipher::default(),
            cipher_text: vec![],
            cipher_params: CipherParams::default(),
            kdf: Kdf::default(),
            kdfparams_dklen: DEFAULT_DK_LENGTH,
            kdfparams_salt: Salt::default(),
            mac: Mac::default(),
        }
    }
}

impl Into<KeyFile> for CoreCrypto {
    fn into(self) -> KeyFile {
        KeyFile {
            crypto: CryptoType::Core(self),
            ..Default::default()
        }
    }
}

impl Decodable for CoreCrypto {
    fn decode<D: Decoder>(d: &mut D) -> Result<CoreCrypto, D::Error> {
        d.read_struct("Crypto", 6, |d| {
            let cipher = d.read_struct_field("cipher", 0, |d| decode_str(d))?;

            let cipher_params =
                d.read_struct_field("cipherparams", 1, |d| CipherParams::decode(d))?;

            let cipher_text = d.read_struct_field("ciphertext", 2, |d| {
                d.read_str()
                    .and_then(|s| Vec::from_hex(s).map_err(|e| d.error(&e.to_string())))
            })?;

            let mut kdf = d.read_struct_field("kdf", 3, |d| decode_str(d))?;

            let (dklen, salt) = d.read_struct_field("kdfparams", 4, |d| match kdf {
                Kdf::Pbkdf2 {
                    ref mut prf,
                    ref mut c,
                } => d.read_struct("KdfParams", 4, |d| {
                    let dklen = d.read_struct_field("dklen", 0, |d| d.read_usize())?;
                    let salt = d.read_struct_field("salt", 1, |d| Salt::decode(d))?;

                    *prf = d.read_struct_field("prf", 2, |d| decode_str(d))?;
                    *c = d.read_struct_field("c", 3, |d| d.read_u32())?;

                    Ok((dklen, salt))
                }),
                Kdf::Scrypt {
                    ref mut n,
                    ref mut r,
                    ref mut p,
                } => d.read_struct("KdfParams", 5, |d| {
                    let dklen = d.read_struct_field("dklen", 0, |d| d.read_usize())?;
                    let salt = d.read_struct_field("salt", 1, |d| Salt::decode(d))?;

                    *n = d.read_struct_field("n", 2, |d| d.read_u32())?;
                    *r = d.read_struct_field("r", 3, |d| d.read_u32())?;
                    *p = d.read_struct_field("p", 4, |d| d.read_u32())?;

                    Ok((dklen, salt))
                }),
            })?;

            let mac = d.read_struct_field("mac", 5, |d| Mac::decode(d))?;

            Ok(CoreCrypto {
                cipher,
                cipher_text,
                cipher_params,
                kdf,
                kdfparams_dklen: dklen,
                kdfparams_salt: salt,
                mac,
            })
        })
    }
}

impl Encodable for CoreCrypto {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_struct("Crypto", 6, |s| {
            s.emit_struct_field("cipher", 0, |s| s.emit_str(&self.cipher.to_string()))?;
            s.emit_struct_field("cipherparams", 1, |s| self.cipher_params.encode(s))?;
            s.emit_struct_field("ciphertext", 2, |s| self.cipher_text.to_hex().encode(s))?;
            s.emit_struct_field("kdf", 3, |s| s.emit_str(&self.kdf.to_string()))?;
            s.emit_struct_field("kdfparams", 4, |s| match self.kdf {
                Kdf::Pbkdf2 { prf, c } => s.emit_struct("KdfParams", 4, |s| {
                    s.emit_struct_field("dklen", 0, |s| s.emit_usize(self.kdfparams_dklen))?;
                    s.emit_struct_field("salt", 1, |s| self.kdfparams_salt.encode(s))?;
                    s.emit_struct_field("prf", 2, |s| s.emit_str(&prf.to_string()))?;
                    s.emit_struct_field("c", 3, |s| s.emit_u32(c))?;

                    Ok(())
                }),
                Kdf::Scrypt { n, r, p } => s.emit_struct("KdfParams", 5, |s| {
                    s.emit_struct_field("dklen", 0, |s| s.emit_usize(self.kdfparams_dklen))?;
                    s.emit_struct_field("salt", 1, |s| self.kdfparams_salt.encode(s))?;
                    s.emit_struct_field("n", 2, |s| s.emit_u32(n))?;
                    s.emit_struct_field("r", 3, |s| s.emit_u32(r))?;
                    s.emit_struct_field("p", 4, |s| s.emit_u32(p))?;

                    Ok(())
                }),
            })?;
            s.emit_struct_field("mac", 5, |s| self.mac.encode(s))?;

            Ok(())
        })
    }
}

/// Decode string for JSON deserialization
#[inline]
pub fn decode_str<T: FromStr, D: Decoder>(d: &mut D) -> Result<T, D::Error>
where
    <T as FromStr>::Err: ::std::fmt::Display,
{
    d.read_str()
        .and_then(|s| T::from_str(&s).map_err(|e| d.error(&e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystore::Prf;
    use tests::*;

    const PBKDF2_TEXT: &'static str = r#"{
      "cipher": "aes-128-ctr",
      "cipherparams": {
        "iv": "58d54158c3e27131b0a0f2b91201aedc"
      },
      "ciphertext": "9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126",
      "kdf": "pbkdf2",
      "kdfparams": {
        "c": 10240,
        "dklen": 32,
        "prf": "hmac-sha256",
        "salt": "095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b"
      },
      "mac": "83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63"
    }"#;

    const SCRYPT_TEXT: &'static str = r#"{
      "ciphertext": "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1",
      "cipherparams": {
        "iv": "9df1649dd1c50f2153917e3b9e7164e9"
      },
      "cipher": "aes-128-ctr",
      "kdf": "scrypt",
      "kdfparams": {
        "dklen": 32,
        "salt": "fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4",
        "n": 1024,
        "r": 8,
        "p": 1
      },
      "mac": "9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5"
    }"#;

    #[test]
    fn should_serialize_pbkdf2_crypto() {
        let exp = CoreCrypto {
            cipher: Cipher::default(),
            cipher_text: Vec::from_hex(
                "9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126",
            ).unwrap(),
            cipher_params: CipherParams {
                iv: json::decode("\"58d54158c3e27131b0a0f2b91201aedc\"").unwrap(),
            },
            kdf: Kdf::Pbkdf2 {
                prf: Prf::default(),
                c: 10240,
            },
            kdfparams_dklen: 32,
            kdfparams_salt: json::decode(
                "\"095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b\"",
            ).unwrap(),
            mac: json::decode(
                "\"83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63\"",
            ).unwrap(),
        };

        // just first encoding
        let act = json::decode::<CoreCrypto>(PBKDF2_TEXT).unwrap();

        // verify encoding & decoding full cycle logic
        let act = json::decode::<CoreCrypto>(&json::encode(&act).unwrap()).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_serialize_scrypt_crypto() {
        let exp = CoreCrypto {
            cipher: Cipher::default(),
            cipher_text: Vec::from_hex(
                "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1",
            ).unwrap(),
            cipher_params: CipherParams {
                iv: json::decode("\"9df1649dd1c50f2153917e3b9e7164e9\"").unwrap(),
            },
            kdf: Kdf::Scrypt {
                n: 1024,
                r: 8,
                p: 1,
            },
            kdfparams_dklen: 32,
            kdfparams_salt: json::decode(
                "\"fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4\"",
            ).unwrap(),
            mac: json::decode(
                "\"9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5\"",
            ).unwrap(),
        };

        // just first encoding
        let act = json::decode::<CoreCrypto>(SCRYPT_TEXT).unwrap();

        // verify encoding & decoding full cycle logic
        let act = json::decode::<CoreCrypto>(&json::encode(&act).unwrap()).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_not_decode_unknown_kdf_prf() {
        let text = PBKDF2_TEXT.replace(&Prf::default().to_string(), "unknown");

        assert!(json::decode::<CoreCrypto>(&text).is_err());
    }

    #[test]
    fn should_not_decode_unknown_cipher() {
        let text = SCRYPT_TEXT.replace(&Cipher::default().to_string(), "unknown");

        assert!(json::decode::<CoreCrypto>(&text).is_err());
    }

    #[test]
    fn should_not_decode_not_wrong_crypto() {
        assert!(json::decode::<CoreCrypto>("garbage").is_err());
    }
}
