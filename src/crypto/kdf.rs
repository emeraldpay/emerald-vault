use crate::{
    crypto::error::CryptoError,
    structs::crypto::{Kdf, Pbkdf2, PrfType, ScryptKdf},
};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use scrypt::{scrypt, ScryptParams};
use sha2::{Sha256, Sha512};
use crate::structs::crypto::Argon2;

/// Key Derivation source
pub trait KeyDerive {
    fn derive(&self, password: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

impl KeyDerive for Pbkdf2 {
    fn derive(&self, password: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut key = vec![0u8; self.dklen as usize];
        match self.prf {
            PrfType::HmacSha256 => {
                pbkdf2::<Hmac<Sha256>>(password, &self.salt, self.c, &mut key)
            }
            PrfType::HmacSha512 => {
                pbkdf2::<Hmac<Sha512>>(password, &self.salt, self.c, &mut key)
            }
        };
        Ok(key.to_vec())
    }
}

impl KeyDerive for ScryptKdf {
    fn derive(&self, password: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let log_n = (self.n as f64).log2().round() as u8;
        let mut key = vec![0u8; self.dklen as usize];
        let params = ScryptParams::new(log_n, self.r, self.p)?;
        scrypt(password, &self.salt, &params, &mut key)?;
        Ok(key)
    }
}

impl KeyDerive for Argon2 {
    fn derive(&self, password: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let kdf = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::default(),
            argon2::Params::new(
                self.mem,
                self.iterations,
                self.parallel,
                Some(32),
            )?,
        );
        let mut key = vec![0u8; 32];
        kdf.hash_password_into(password, self.salt.as_slice(), &mut key)?;
        Ok(key)
    }
}

impl KeyDerive for Kdf {
    fn derive(&self, password: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match &self {
            Kdf::Scrypt(v) => v.derive(password),
            Kdf::Pbkdf2(v) => v.derive(password),
            Kdf::Argon2(v) => v.derive(password),
        }
    }
}

impl ScryptKdf {
    pub fn create_with_salt(salt: [u8; 32]) -> Self {
        ScryptKdf {
            dklen: 32,
            salt: salt.to_vec(),
            n: 8192,
            r: 8,
            p: 1,
        }
    }
}

impl Argon2 {
    pub fn create_with_salt(salt: Vec<u8>) -> Self {
        Argon2 {
            mem: 4096,
            iterations: 4,
            parallel: 4,
            salt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;

    #[test]
    fn derive_official_eth_pbkdf2() {
        let kdf = Pbkdf2 {
            dklen: 32,
            c: 8,
            salt: hex::decode("ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd")
                .unwrap(),
            prf: PrfType::HmacSha256,
        };

        assert_eq!(
            hex::encode(kdf.derive("testpassword".as_bytes()).unwrap()),
            "031dc7e0f4f375f6d6fdab7ad8d71834d844e39a6b62f9fb98d942bab76db0f9"
        );
    }

    #[test]
    fn derive_official_eth_slow_pbkdf2() {
        // https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
        let kdf = Pbkdf2 {
            dklen: 32,
            salt: hex::decode("ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd")
                .unwrap(),
            c: 262144,
            prf: PrfType::HmacSha256,
        };

        assert_eq!(
            hex::encode(kdf.derive("testpassword".as_bytes()).unwrap()),
            "f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551"
        );
    }

    #[test]
    fn derive_fast_pbkdf2_32() {
        let kdf = Pbkdf2 {
            dklen: 32,
            c: 1024,
            salt: hex::decode("07739140252caf31150004f25f0d0b918e41c82ca9a49c12742461a9c28a1033")
                .unwrap(),
            prf: PrfType::HmacSha256,
        };

        assert_eq!(
            hex::encode(kdf.derive("test".as_bytes()).unwrap()),
            "392e7c4eef16f9b76db1ffe581c6a15a636df41ba8ff29c5f87ee1d394ed5dc4",
        );
    }

    #[test]
    fn derive_fast_pbkdf2_64() {
        let kdf = Pbkdf2 {
            dklen: 64,
            c: 1024,
            salt: hex::decode("07739140252caf31150004f25f0d0b918e41c82ca9a49c12742461a9c28a1033")
                .unwrap(),
            prf: PrfType::HmacSha256,
        };

        assert_eq!(
            hex::encode(kdf.derive("test".as_bytes()).unwrap()),
            "392e7c4eef16f9b76db1ffe581c6a15a636df41ba8ff29c5f87ee1d394ed5dc41e5f9635e2e31508584fbd96074f65491d70e2461c350857caa380c26f197efd"
        );
    }

    #[test]
    fn derive_fast_pbkdf2_32_sha512() {
        let kdf = Pbkdf2 {
            dklen: 32,
            c: 1024,
            salt: hex::decode("07739140252caf31150004f25f0d0b918e41c82ca9a49c12742461a9c28a1033")
                .unwrap(),
            prf: PrfType::HmacSha512,
        };

        assert_eq!(
            hex::encode(kdf.derive("test".as_bytes()).unwrap()),
            "c4a572112f57cf020fdc7825b5cb251667ce3f8dc5d06b6ca98b75e40f805f9e"
        );
    }

    #[test]
    fn derive_ultrafast_scrypt_32() {
        let kdf = ScryptKdf {
            dklen: 32,
            salt: hex::decode("fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4")
                .unwrap(),
            n: 2,
            r: 8,
            p: 1,
        };

        assert_eq!(
            hex::encode(kdf.derive("1234567890".as_bytes()).unwrap()),
            "52a5dacfcf80e5111d2c7fbed177113a1b48a882b066a017f2c856086680fac7"
        );
    }

    #[test]
    fn derive_scrypt_fast_32() {
        let kdf = ScryptKdf {
            dklen: 32,
            salt: hex::decode("d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e")
                .unwrap(),
            n: 1024,
            r: 8,
            p: 1,
        };

        assert_eq!(
            hex::encode(kdf.derive("testtest".as_bytes()).unwrap()),
            "dae0d1db4b5d5885db2a0a3f245b83923945d593277bbf4aa840fa497eb20026"
        );
    }

    #[test]
    fn derive_scrypt_fast_64() {
        let kdf = ScryptKdf {
            dklen: 64,
            salt: hex::decode("d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e")
                .unwrap(),
            n: 1024,
            r: 8,
            p: 1,
        };

        assert_eq!(
            hex::encode(kdf.derive("testtest".as_bytes()).unwrap()),
            "dae0d1db4b5d5885db2a0a3f245b83923945d593277bbf4aa840fa497eb20026cb90e037fb92ed2d81195666d1fb9c15d4a4c0975786d126f0a7b22942887212"
        );
    }

    #[test]
    fn derive_scrypt_slow_32() {
        let kdf = ScryptKdf {
            dklen: 32,
            salt: hex::decode("d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e")
                .unwrap(),
            n: 16384,
            r: 8,
            p: 1,
        };

        assert_eq!(
            hex::encode(kdf.derive("testtest".as_bytes()).unwrap()),
            "41db5e54866d6d8be8a9576786f53e5ae2c1a85e334709a8f190236ce4e4f1a5"
        );
    }

    #[test]
    fn derive_scrypt_slow_64() {
        let kdf = ScryptKdf {
            dklen: 64,
            salt: hex::decode("d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e")
                .unwrap(),
            n: 16384,
            r: 8,
            p: 1,
        };

        assert_eq!(
            hex::encode(kdf.derive("testtest".as_bytes()).unwrap()),
            "41db5e54866d6d8be8a9576786f53e5ae2c1a85e334709a8f190236ce4e4f1a585fdb308a2930bfb6ed1d88b6e898c95dbda24a359d68278e4148a60642fa6e3"
        );
    }

    #[test]
    fn derive_scrypt_with_zero() {
        let kdf = ScryptKdf {
            dklen: 32,
            salt: hex::decode("7dc589ffcb9766699442ff5b0f254bd9455861cd00019e5617b99c0dd507eff8")
                .unwrap(),
            n: 1024,
            r: 8,
            p: 1,
        };

        assert_eq!(
            hex::encode(kdf.derive("test12345678".as_bytes()).unwrap()),
            "04b4115dc5134213bf6d2af6632b9f0352777f40fdaa4543bccd7d4573f52868"
        );
    }

    #[test]
    fn derive_argon2() {
        let kdf = Argon2::create_with_salt(
            hex::decode("fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4").unwrap()
        );

        assert_eq!(
            hex::encode(kdf.derive("1234567890".as_bytes()).unwrap()),
            "9e56e4faa4b75909c74e4e3e73726254864411542a04dc236f712b7801b651a4"
        );
    }
}
