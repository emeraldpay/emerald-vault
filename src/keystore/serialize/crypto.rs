//! # JSON serialize for crypto field (UTC / JSON)

use keystore::{CIPHER_IV_BYTES, Cipher, KDF_SALT_BYTES, KECCAK256_BYTES, Kdf, KeyFile, Prf};
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use rustc_serialize::hex::{FromHex, ToHex};
use std::str::FromStr;

byte_array_struct!(Salt, KDF_SALT_BYTES);
byte_array_struct!(Mac, KECCAK256_BYTES);
byte_array_struct!(Iv, CIPHER_IV_BYTES);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crypto {
    cipher: Cipher,
    cipher_text: Vec<u8>,
    cipher_params: CipherParams,
    kdf: Kdf,
    kdfparams_dklen: u32,
    kdfparams_salt: Salt,
    mac: Mac,
}

#[derive(Clone, Debug, PartialEq, Eq, RustcDecodable, RustcEncodable)]
struct CipherParams {
    iv: Iv,
}

impl From<Crypto> for KeyFile {
    fn from(crypto: Crypto) -> Self {
        KeyFile {
            dk_length: crypto.kdfparams_dklen,
            kdf: crypto.kdf,
            kdf_salt: crypto.kdfparams_salt.into(),
            keccak256_mac: crypto.mac.into(),
            cipher: crypto.cipher,
            cipher_text: crypto.cipher_text.clone(),
            cipher_iv: crypto.cipher_params.iv.into(),
            ..KeyFile::default()
        }
    }
}

impl From<KeyFile> for Crypto {
    fn from(key_file: KeyFile) -> Self {
        Crypto {
            cipher: key_file.cipher,
            cipher_text: key_file.cipher_text,
            cipher_params: CipherParams { iv: Iv::from(key_file.cipher_iv) },
            kdf: key_file.kdf,
            kdfparams_dklen: key_file.dk_length,
            kdfparams_salt: Salt::from(key_file.kdf_salt),
            mac: Mac::from(key_file.keccak256_mac),
        }
    }
}

impl Decodable for Crypto {
    fn decode<D: Decoder>(d: &mut D) -> Result<Crypto, D::Error> {
        d.read_struct("Crypto", 6, |d| {
            let cipher = (d.read_struct_field("cipher", 0, |d| {
                d.read_str()
                    .and_then(|s| Cipher::from_str(&s).map_err(|e| d.error(&e.to_string())))
            }))?;

            let cipher_params =
                (d.read_struct_field("cipherparams", 1, |d| CipherParams::decode(d)))?;

            let cipher_text = (d.read_struct_field("ciphertext", 2, |d| {
                d.read_str()
                    .and_then(|s| s.from_hex().map_err(|e| d.error(&e.to_string())))
            }))?;

            let mut kdf = (d.read_struct_field("kdf", 3, |d| {
                d.read_str()
                    .and_then(|s| Kdf::from_str(&s).map_err(|e| d.error(&e.to_string())))
            }))?;

            let (dklen, salt) = (d.read_struct_field("kdfparams", 4, |d| match kdf {
                Kdf::Pbkdf2 {
                    ref mut prf,
                    ref mut c,
                } => {
                    d.read_struct("KdfParams", 4, |d| {
                        let dklen = d.read_struct_field("dklen", 0, |d| d.read_u32())?;
                        let salt = d.read_struct_field("salt", 1, |d| Salt::decode(d))?;

                        *prf = d.read_struct_field("prf", 2, |d| {
                                d.read_str().and_then(|s| {
                                Prf::from_str(&s).map_err(|e| d.error(&e.to_string()))
                            })
                            })?;
                        *c = d.read_struct_field("c", 3, |d| d.read_u32())?;

                        Ok((dklen, salt))
                    })
                }
                Kdf::Scrypt {
                    ref mut n,
                    ref mut r,
                    ref mut p,
                } => {
                    d.read_struct("KdfParams", 5, |d| {
                        let dklen = d.read_struct_field("dklen", 0, |d| d.read_u32())?;
                        let salt = d.read_struct_field("salt", 1, |d| Salt::decode(d))?;

                        *n = d.read_struct_field("n", 2, |d| d.read_u32())?;
                        *r = d.read_struct_field("r", 3, |d| d.read_u32())?;
                        *p = d.read_struct_field("p", 4, |d| d.read_u32())?;

                        Ok((dklen, salt))
                    })
                }
            }))?;

            let mac = (d.read_struct_field("mac", 5, |d| Mac::decode(d)))?;

            Ok(Crypto {
                   cipher: cipher,
                   cipher_text: cipher_text,
                   cipher_params: cipher_params,
                   kdf: kdf,
                   kdfparams_dklen: dklen,
                   kdfparams_salt: salt,
                   mac: mac,
               })
        })
    }
}

impl Encodable for Crypto {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_struct("Crypto", 6, |s| {
            (s.emit_struct_field("cipher", 0, |s| s.emit_str(&self.cipher.to_string())))?;
            (s.emit_struct_field("cipherparams", 1, |s| self.cipher_params.encode(s)))?;
            (s.emit_struct_field("ciphertext", 2, |s| self.cipher_text.to_hex().encode(s)))?;
            (s.emit_struct_field("kdf", 3, |s| s.emit_str(&self.kdf.to_string())))?;
            (s.emit_struct_field("kdfparams", 4, |s| match self.kdf {
                Kdf::Pbkdf2 { prf, c } => {
                    s.emit_struct("KdfParams", 4, |s| {
                        (s.emit_struct_field("dklen", 0, |s| s.emit_u32(self.kdfparams_dklen)))?;
                        (s.emit_struct_field("salt", 1, |s| self.kdfparams_salt.encode(s)))?;
                        (s.emit_struct_field("prf", 2, |s| s.emit_str(&prf.to_string())))?;
                        (s.emit_struct_field("c", 3, |s| s.emit_u32(c)))?;

                        Ok(())
                    })
                }
                Kdf::Scrypt { n, r, p } => {
                    s.emit_struct("KdfParams", 5, |s| {
                        (s.emit_struct_field("dklen", 0, |s| s.emit_u32(self.kdfparams_dklen)))?;
                        (s.emit_struct_field("salt", 1, |s| self.kdfparams_salt.encode(s)))?;
                        (s.emit_struct_field("n", 2, |s| s.emit_u32(n)))?;
                        (s.emit_struct_field("r", 3, |s| s.emit_u32(r)))?;
                        (s.emit_struct_field("p", 4, |s| s.emit_u32(p)))?;

                        Ok(())
                    })
                }
            }))?;
            (s.emit_struct_field("mac", 5, |s| self.mac.encode(s)))?;

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CipherParams, Crypto};
    use keystore::{Cipher, Kdf, Prf};
    use rustc_serialize::hex::FromHex;
    use rustc_serialize::json;

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
        let exp = Crypto {
            cipher: Cipher::default(),
            cipher_text: "9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126"
                .from_hex()
                .unwrap(),
            cipher_params: CipherParams {
                iv: json::decode("\"58d54158c3e27131b0a0f2b91201aedc\"").unwrap(),
            },
            kdf: Kdf::Pbkdf2 {
                prf: Prf::default(),
                c: 10240,
            },
            kdfparams_dklen: 32,
            kdfparams_salt:
                json::decode("\"095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b\"")
                    .unwrap(),
            mac:
                json::decode("\"83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63\"")
                    .unwrap(),
        };

        // just first encoding
        let act = json::decode::<Crypto>(PBKDF2_TEXT).unwrap();

        // verify encoding & decoding full cycle logic
        let act = json::decode::<Crypto>(&json::encode(&act).unwrap()).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_serialize_scrypt_crypto() {
        let exp = Crypto {
            cipher: Cipher::default(),
            cipher_text: "c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1"
                .from_hex()
                .unwrap(),
            cipher_params: CipherParams {
                iv: json::decode("\"9df1649dd1c50f2153917e3b9e7164e9\"").unwrap(),
            },
            kdf: Kdf::Scrypt {
                n: 1024,
                r: 8,
                p: 1,
            },
            kdfparams_dklen: 32,
            kdfparams_salt:
                json::decode("\"fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4\"")
                    .unwrap(),
            mac:
                json::decode("\"9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5\"")
                    .unwrap(),
        };

        // just first encoding
        let act = json::decode::<Crypto>(SCRYPT_TEXT).unwrap();

        // verify encoding & decoding full cycle logic
        let act = json::decode::<Crypto>(&json::encode(&act).unwrap()).unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    fn should_not_decode_unknown_kdf_prf() {
        let text = PBKDF2_TEXT.replace(&Prf::default().to_string(), "unknown");

        assert!(json::decode::<Crypto>(&text).is_err());
    }

    #[test]
    fn should_not_decode_unknown_cipher() {
        let text = SCRYPT_TEXT.replace(&Cipher::default().to_string(), "unknown");

        assert!(json::decode::<Crypto>(&text).is_err());
    }

    #[test]
    fn should_not_decode_not_wrong_crypto() {
        assert!(json::decode::<Crypto>("garbage").is_err());
    }
}
