

#[cfg(test)]
mod test {
    use hex::FromHex;
    use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
    use secp256k1::Secp256k1;
    use bitcoin::util::bip32::ChildNumber::{Hardened, Normal};
    use bitcoin::network::constants::Network;
    use core::{Address, PrivateKey};
    use std::str::FromStr;
    use mnemonic::{Mnemonic, Language};

    #[test]
    fn test_key_generation() {
        let s = "beyond stage sleep clip because twist token leaf atom beauty \
            genius food business side grid unable middle armed observe pair crouch tonight \
            away coconut";
        let mnemonic = Mnemonic::try_from(Language::English, s).unwrap();
        let w: Vec<String> = s.to_string()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();
        assert_eq!(w, mnemonic.words);

        let seed = Vec::from_hex("b15509eaa2d09d3efd3e006ef42151b3\
            0367dc6e3aa5e44caba3fe4d3e352e65\
            101fbdb86a96776b91946ff06f8eac59\
            4dc6ee1d3e82a42dfe1b40fef6bcc3fd").unwrap();
        assert_eq!(mnemonic.seed("TREZOR"), seed);

        let secp = Secp256k1::new();
        let path = &[Hardened(44), Hardened(60), Hardened(160720), Hardened(0), Normal(0)];

        let mut sk = ExtendedPrivKey::new_master(&secp, Network::Bitcoin, &seed).unwrap();
        let mut pk = ExtendedPubKey::from_private(&secp, &sk);
        // Derive keys, checking hardened and non-hardened derivation
        for &num in path.iter() {
            sk = sk.ckd_priv(&secp, num).unwrap();
            match num {
                Normal(_) => {
                    let pk2 = pk.ckd_pub(&secp, num).unwrap();
                    pk = ExtendedPubKey::from_private(&secp, &sk);
                    assert_eq!(pk, pk2);
                }
                Hardened(_) => {
                    pk = ExtendedPubKey::from_private(&secp, &sk);
                }
            }
        }
        let priv_key = PrivateKey::try_from(&sk.secret_key[0..32]).unwrap();

//        println!(">> DEBUG address: {}", priv_key.to_address().unwrap());
//        println!(">> DEBUG private key: {}", priv_key.to_string());

        assert_eq!(Address::from_str("0xD7262F153Bcd412DfD000132bdf151263D7C1Ac7").unwrap(), priv_key.to_address().unwrap());
    }

}