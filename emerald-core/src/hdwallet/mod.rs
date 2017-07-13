//! # Module to work with `HD Wallets`
//!
//! `HD(Hierarchical Deterministic) Wallet` specified in
//! [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.medёiawiki)


mod error;
mod apdu;
mod hd_keystore;
mod ledger;

pub use self::error::Error;
use self::ledger::Ledger;
use core::Address;
use core::Transaction;
use u2fhid::{self, U2FManager};
use uuid::Uuid;

/// Model of HD wallet
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletType {
    ///
    LedgerNanoS,
}

pub trait WalletCore: Sized {
    ///
    fn sign_tx(&self, tr: &Vec<u8>, u2f: &U2FManager) -> Result<Vec<u8>, Error>;
}

///
struct HDWallet<T: WalletCore> {
    u2f: u2fhid::U2FManager,
    id: WalletType,
    core: T,
}

impl HDWallet<Ledger> {
    ///
    pub fn create_ledger() -> Result<Self, Error> {
        Ok(HDWallet::<Ledger> {
            u2f: U2FManager::new()?,
            id: WalletType::LedgerNanoS,
            core: Ledger,
        })
    }
}

impl<T: WalletCore> HDWallet<T> {
    ///
    pub fn sign(&self, tr: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.core.sign_tx(tr, &self.u2f)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;
    //
    //    let pk = PrivateKey(to_32bytes(
    //        "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
    //    ));
    //
    //    assert_eq!(tx.to_signed_raw(pk, 61 /*MAINNET_ID*/).unwrap().to_hex(),
    //               "f86d\
    //                   80\
    //                   8504e3b29200\
    //                   825208\
    //                   940000000000000000000000000000000012345678\
    //                   880de0b6b3a7640000\
    //                   80\
    //                   819e\
    //                   a0b17da8416f42d62192b07ff855f4a8e8e9ee1a2e920e3c407fd9a3bd5e388daa\
    //                   a0547981b617c88587bfcd924437f6134b0b75f4484042db0750a2b1c0ccccc597");
    //}

    #[test]
    pub fn should_sign_with_ledger() {
        let tx = Transaction {
            nonce: 0,
            gas_price: /* 21000000000 */
            to_32bytes("0000000000000000000000000000000\
                                          0000000000000000000000004e3b29200"),
            gas_limit: 21000,
            to: Some("0x0000000000000000000000000000000012345678"
                .parse::<Address>()
                .unwrap()),
            value: /* 1 ETC */
            to_32bytes("00000000000000000000000000000000\
                                          00000000000000000de0b6b3a7640000"),
            data: Vec::new(),
        };

        /*
            {
               "nonce":"0x00",
               "gasPrice":"0x04e3b29200",
               "gasLimit":"0x5208",
               "to":"0x0000000000000000000000000000000012345678",
               "value":"0x0de0b6b3a7640000",
               "data":"",
               "chainId":61
            }
        */
        println!("RLP packed transaction: {:?}", &tx.to_rlp().tail);

        let wallet = HDWallet::create_ledger().unwrap();
        println!("signed with wallet {:?}", wallet.sign(&tx.to_rlp().tail).unwrap());
    }
}
