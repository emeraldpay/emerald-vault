/*
Copyright 2019 ETCDEV GmbH
Copyright 2020 EmeraldPay, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//! # Module to work with `HD Wallets`
//!
//! Currently supports only Ledger Nano S & Ledger Blue
//! `HD(Hierarchical Deterministic) Wallet` specified in
//! [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

mod apdu;
pub mod bip32;
mod comm;
mod error;

use self::apdu::ApduBuilder;
use self::comm::sendrecv;
pub use self::error::Error;
use super::{to_arr, Address, Signature, ECDSA_SIGNATURE_BYTES};
use bip32::HDPath;
use hex;
use hidapi::{HidApi, HidDevice, HidDeviceInfo};
use std::str::{from_utf8, FromStr};
use std::{thread, time};
use crate::hdwallet::comm::ping;

const GET_ETH_ADDRESS: u8 = 0x02;
const SIGN_ETH_TRANSACTION: u8 = 0x04;
const CHUNK_SIZE: usize = 255;

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_S_PID_1: u16 = 0x0001; // for Nano S model with Bitcoin App
const LEDGER_S_PID_2: u16 = 0x1011; // for Nano S model without any app
const LEDGER_S_PID_3: u16 = 0x1015; // for Nano S model with Ethereum or Ethereum Classic App

const LEDGER_X_PID_1: u16 = 0x4011; // for Nano X model (official)
const LEDGER_X_PID_2: u16 = 0x0004; // for Nano X model (in the wild)

const DERIVATION_INDEX_SIZE: usize = 4;

/// Type used for device listing,
/// String corresponds to file descriptor of the device
pub type DevicesList = Vec<(Address, String)>;

///
#[derive(Debug)]
struct Device {
    ///
    fd: String,
    ///
    address: Address,
    ///
    hid_info: HidDeviceInfo,
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        self.fd == other.fd
    }
}

impl From<HidDeviceInfo> for Device {
    fn from(hid_info: HidDeviceInfo) -> Self {
        let info = hid_info.clone();
        Device {
            fd: hid_info.path,
            address: Address::default(),
            hid_info: info,
        }
    }
}

/// `Wallet Manager` to handle all interaction with HD wallet
pub struct WManager {
    /// HID point used for communication
    hid: HidApi,
    /// List of available wallets
    device: Option<Device>,
    /// Derivation path
    hd_path: Option<Vec<u8>>,
}

impl WManager {
    /// Creates new `Wallet Manager` with a specified
    /// derivation path
    pub fn new(hd_path: Option<Vec<u8>>) -> Result<WManager, Error> {
        Ok(Self {
            hid: HidApi::new()?,
            device: None,
            hd_path,
        })
    }

    /// Decides what HD path to use
    fn pick_hd_path(&self, h: Option<Vec<u8>>) -> Result<Vec<u8>, Error> {
        if self.hd_path.is_none() && h.is_none() {
            return Err(Error::HDWalletError("HD path is not specified".to_string()));
        }

        Ok(h.or_else(|| self.hd_path.clone()).unwrap())
    }

    /// Get address
    ///
    /// # Arguments:
    /// fd - file descriptor to corresponding HID device
    /// hd_path - optional HD path, prefixed with count of derivation indexes
    ///
    pub fn get_address(&self, fd: &str, hd_path: Option<Vec<u8>>) -> Result<Address, Error> {
        let hd_path = self.pick_hd_path(hd_path)?;

        let apdu = ApduBuilder::new(GET_ETH_ADDRESS)
            .with_data(&hd_path)
            .build();

        debug!("DEBUG get address: {:?}", &fd);
        let handle = self.open()?;
        let addr = sendrecv(&handle, &apdu)
            .and_then(|res| match res.len() {
                107 => Ok(res),
                _ => Err(Error::HDWalletError(
                    "Address read returned invalid data length".to_string(),
                )),
            })
            .and_then(|res: Vec<u8>| {
                from_utf8(&res[67..107])
                    .map(|ptr| ptr.to_string())
                    .map_err(|e| {
                        Error::HDWalletError(format!("Can't parse address: {}", e.to_string()))
                    })
            })
            .and_then(|s| {
                Address::from_str(&s).map_err(|e| {
                    Error::HDWalletError(format!("Can't parse address: {}", e.to_string()))
                })
            })?;

        Ok(addr)
    }

    /// Sign data
    ///
    /// # Arguments:
    /// fd - file descriptor to corresponding HID device
    /// data - RLP packed data
    /// hd_path - optional HD path, prefixed with count of derivation indexes
    ///
    pub fn sign(
        &self,
        _fd: &str,
        _data: &[u8],
        _hd_path: &Option<Vec<u8>>,
    ) -> Result<Signature, Error> {
        Err(Error::HDWalletError("Can't sign data".to_string()))
    }

    /// Sign transaction
    ///
    /// # Arguments:
    /// fd - file descriptor to corresponding HID device
    /// tr - RLP packed transaction
    /// hd_path - optional HD path, prefixed with count of derivation indexes
    ///
    pub fn sign_transaction(
        &self,
        fd: &str,
        tr: &[u8],
        hd_path: Option<Vec<u8>>,
    ) -> Result<Signature, Error> {
        let hd_path = self.pick_hd_path(hd_path)?;

        let _mock = Vec::new();
        let (init, cont) = match tr.len() {
            0...CHUNK_SIZE => (tr, _mock.as_slice()),
            _ => tr.split_at(CHUNK_SIZE - hd_path.len()),
        };

        let init_apdu = ApduBuilder::new(SIGN_ETH_TRANSACTION)
            .with_p1(0x00)
            .with_data(&hd_path)
            .with_data(init)
            .build();

        if self.device.is_none() {
            return Err(Error::HDWalletError("Device not selected".to_string()))
        }

        let handle = self.open()?;
        let mut res = sendrecv(&handle, &init_apdu)?;

        for chunk in cont.chunks(CHUNK_SIZE) {
            let apdu_cont = ApduBuilder::new(SIGN_ETH_TRANSACTION)
                .with_p1(0x80)
                .with_data(chunk)
                .build();
            res = sendrecv(&handle, &apdu_cont)?;
        }
        debug!("Received signature: {:?}", hex::encode(&res));
        match res.len() {
            ECDSA_SIGNATURE_BYTES => {
                let mut val: [u8; ECDSA_SIGNATURE_BYTES] = [0; ECDSA_SIGNATURE_BYTES];
                val.copy_from_slice(&res);

                Ok(Signature::from(val))
            }
            v => Err(Error::HDWalletError(format!(
                "Invalid signature length. Expected: {}, received: {}",
                ECDSA_SIGNATURE_BYTES, v
            ))),
        }
    }

    /// List all available devices
    pub fn devices(&self) -> DevicesList {
        self.device
            .iter()
            .map(|d| (d.address, d.fd.clone()))
            .collect()
    }

    /// Update device list
    pub fn update(&mut self, hd_path: Option<Vec<u8>>) -> Result<(), Error> {
        let hd_path = self.pick_hd_path(hd_path)?;

        self.hid.refresh_devices();
        debug!("Start searching for devices: {:?}", self.hid.devices());

        let current = self.hid.devices().iter()
            .find(|hid_info|
                 hid_info.vendor_id == LEDGER_VID &&
                    (hid_info.product_id == LEDGER_S_PID_1 || hid_info.product_id == LEDGER_S_PID_2 || hid_info.product_id == LEDGER_S_PID_3
                        || hid_info.product_id == LEDGER_X_PID_1 || hid_info.product_id == LEDGER_X_PID_2)
            ).map(|hid_info| {
                let mut d = Device::from(hid_info.clone());
                match self.get_address(&d.fd, Some(hd_path.clone())) {
                    Ok(address) => d.address = address,
                    Err(_) => {}
                }
                d
            });

        self.device = current;
        Ok(())
    }

    pub fn open(&self) -> Result<HidDevice, Error> {
        if self.device.is_none() {
            return Err(Error::HDWalletError("Device not selected".to_string()))
        }
        let target = match &self.device {
            Some(device) => device,
            None => panic!("Device not selected")
        };
        // up to 10 tries, starting from 100ms increasing by 75ms, in total 1450ms max
        let mut retry_delay = 100;
        for _ in 0..10 { //
            //serial number is always 0001
            if let Ok(h) = self.hid.open(target.hid_info.vendor_id, target.hid_info.product_id) {
                match ping(&h) {
                    Ok(v) => if v {
                        return Ok(h)
                    },
                    Err(_) => {}
                }
            }
            thread::sleep(time::Duration::from_millis(retry_delay));
            retry_delay += 75;
        }

        // used by another application
        Err(Error::HDWalletError(format!(
            "Can't open device: {:?}", target.hid_info
        )))
    }
}

#[cfg(test)]
pub mod test_commons {
    use std::env;
    use std::fs;
    use crate::Address;

    #[derive(Deserialize)]
    pub struct TestAddress {
        pub hdpath: String,
        pub address: Address
    }

    #[derive(Deserialize)]
    pub struct TestTx {
        pub id: String,
        pub description: Option<String>,
        pub from: Option<String>,
        pub raw: String
    }


    pub fn is_ledger_enabled() -> bool {
        match env::var("EMRLD_TEST_LEDGER") {
            Ok(v) => v == "true",
            Err(_) => false,
        }
    }

    /// Config:
    /// * ADDR0 - address on 44'/60'/160720'/0'/0
    /// * SIGN1 - hex of a signed transaction, 1 ETH to 78296F1058dD49C5D6500855F59094F0a2876397, nonce 0, gas_price 21 gwei, gas 21000
    pub fn get_ledger_conf(name: &str) -> String {
        let mut path = String::new();
        path.push_str("EMRLD_TEST_LEDGER_");
        path.push_str(name);
        match env::var(path) {
            Ok(v) => v,
            Err(_) => "NOT_SET".to_string(),
        }
    }

    pub fn read_test_addresses() -> Vec<TestAddress> {
        let json = fs::read_to_string("./tests/hdwallet/address.json").expect("tests/hdwallet/address.json is not available");
        let result: Vec<TestAddress> = serde_json::from_str(json.as_str()).expect("Invalid JSON");
        result
    }

    pub fn read_test_txes() -> Vec<TestTx> {
        let json = fs::read_to_string("./tests/hdwallet/tx.json").expect("tests/hdwallet/tx.json is not available");
        let result: Vec<TestTx> = serde_json::from_str(json.as_str()).expect("Invalid JSON");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Transaction;
    use crate::hdwallet::bip32::{path_to_arr, to_prefixed_path};
    use crate::hdwallet::test_commons::{get_ledger_conf, is_ledger_enabled, read_test_addresses, read_test_txes};
    use crate::tests::*;
    use hex;
    use log::{LevelFilter, Level};
    use simple_logger::init_with_level;
    use crate::core::chains::{Blockchain, EthereumChainId};

    pub const ETC_DERIVATION_PATH: [u8; 21] = [
        5, 0x80, 0, 0, 44, 0x80, 0, 0, 60, 0x80, 0x02, 0x73, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]; // 44'/60'/160720'/0/0

    #[test]
    pub fn should_sign_eth() {
        if !is_ledger_enabled() {
            warn!("Ledger test is disabled");
            return;
        }
        let mut manager = WManager::new(Some(ETC_DERIVATION_PATH.to_vec())).unwrap();
        manager.update(None).unwrap();

        let tx = Transaction {
            nonce: 0x00,
            gas_price: /* 21000000000 */
            to_32bytes("0000000000000000000000000000000\
                                          0000000000000000000000004e3b29200"),
            gas_limit: 0x5208,
            to: Some("78296F1058dD49C5D6500855F59094F0a2876397"
                .parse::<Address>()
                .unwrap()),
            value: /* 1 ETC */
            to_32bytes("00000000000000000000000000000000\
                                00000000000000000de0b6b3a7640000"),
            data: Vec::new(),
        };

        let test_txes = read_test_txes();
        let exp = &test_txes[2];
        let from = exp.from.as_ref().unwrap();
        let from = HDPath::try_from(from.as_str()).expect("invalid from");

        let chain: u8 = EthereumChainId::from(Blockchain::Ethereum).as_chainid();
        let rlp = tx.to_rlp(Some(chain));
        let fd = &manager.devices()[0].1;
        let sign = manager.sign_transaction(&fd, &rlp, Some(from.to_bytes())).unwrap();

        let signed = hex::encode(tx.raw_from_sig(None, &sign));

        assert_eq!(exp.raw, signed);
    }

    #[test]
    pub fn should_sign_etc() {
        if !is_ledger_enabled() {
            warn!("Ledger test is disabled");
            return;
        }
        let mut manager = WManager::new(Some(ETC_DERIVATION_PATH.to_vec())).unwrap();
        manager.update(None).unwrap();

        let tx = Transaction {
            nonce: 0x05,
            gas_price: /* 21000000000 */
                to_32bytes("00000000000000000000000000000000000000000000000000000004e3b29200"),
            gas_limit: 0x5208,
            to: Some("78296F1058dD49C5D6500855F59094F0a2876397".parse::<Address>().unwrap()),
            value: /* 1 ETC */
                to_32bytes("0000000000000000000000000000000000000000000000000de0b6b3a7640000"),
            data: Vec::new(),
        };

        let test_txes = read_test_txes();
        let exp = &test_txes[1];
        let from = exp.from.as_ref().unwrap();
        let from = HDPath::try_from(from.as_str()).expect("invalid from");

        let chain: u8 = EthereumChainId::from(Blockchain::EthereumClassic).as_chainid();
        let rlp = tx.to_rlp(Some(chain));
        let fd = &manager.devices()[0].1;
        let sign = manager.sign_transaction(&fd, &rlp, Some(from.to_bytes())).unwrap();

        let signed = hex::encode(tx.raw_from_sig(None, &sign));
        assert_eq!(exp.raw, signed);
    }

    #[test]
    pub fn should_sign_kovan() {
        if !is_ledger_enabled() {
            warn!("Ledger test is disabled");
            return;
        }
        let mut manager = WManager::new(Some(ETC_DERIVATION_PATH.to_vec())).unwrap();
        manager.update(None).unwrap();

        let tx = Transaction {
            nonce: 0x05,
            gas_price: /* 21000000000 */
            to_32bytes("00000000000000000000000000000000000000000000000000000004e3b29200"),
            gas_limit: 0x5208,
            to: Some("78296F1058dD49C5D6500855F59094F0a2876397".parse::<Address>().unwrap()),
            value: /* 1 ETC */
            to_32bytes("0000000000000000000000000000000000000000000000000de0b6b3a7640000"),
            data: Vec::new(),
        };

        let test_txes = read_test_txes();
        let exp = &test_txes[3];
        let from = exp.from.as_ref().unwrap();
        let from = HDPath::try_from(from.as_str()).expect("invalid from");

        let chain: u8 = EthereumChainId::from(Blockchain::KovanTestnet).as_chainid();
        let rlp = tx.to_rlp(Some(chain));
        let fd = &manager.devices()[0].1;
        let sign = manager.sign_transaction(&fd, &rlp, Some(from.to_bytes())).unwrap();

        let signed = hex::encode(tx.raw_from_sig(None, &sign));
        assert_eq!(exp.raw, signed);
    }

    #[test]
    #[ignore] //we don't sign anything except simple tx yet
    pub fn should_sign_with_ledger_big_data() {
        // simple_logger::init_with_level(Level::Trace);
        if !is_ledger_enabled() {
            warn!("Ledger test is disabled");
            return;
        }
        let mut manager = WManager::new(Some(ETC_DERIVATION_PATH.to_vec())).unwrap();
        manager.update(None).unwrap();

        let mut data = Vec::new();

        // create 512 bytes of data,
        // fill with `11cccccccccccc11` 8-byte hex fragment
        for _ in 0..64 {
            data.push(0x11);
            data.extend_from_slice(&[0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc]);
            data.push(0x11);
        }
        let tx = Transaction {
            nonce: 0x01,
            gas_price: /* 21000000000 */
            to_32bytes("0000000000000000000000000000000\
                                          0000000000000000000000004e3b29200"),
            gas_limit: 0x5208,
            to: Some("c0de379b51d582e1600c76dd1efee8ed024b844a"
                .parse::<Address>()
                .unwrap()),
            value: /* 1 ETC */
            to_32bytes("00000000000000000000000000000000\
                                          00000000000000000003f26fcfb7a224"),
            data: data,
        };

        let rlp = tx.to_rlp(None);
        let fd = &manager.devices()[0].1;
        /*
            f9\
            022a01\
            \
            85\
            04e3b29200\
            \
            82\
            5208\
            \
            94\
            c0de379b51d582e1600c76dd1efee8ed024b844a\
            \
            87\
            03f26fcfb7a224\
            \
            b9\
            0200\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11\
            11cccccccccccc1111cccccccccccc1111cccccccccccc1111cccccccccccc11
        */
        println!(">> RLP: {:?}", hex::encode(&rlp));
        let sign = manager.sign_transaction(&fd, &rlp, None);
        assert!(sign.is_ok());
        debug!("Signature: {:?}", &sign.unwrap());
    }

    #[test]
    pub fn should_get_address_with_ledger() {
        simple_logger::init_with_level(Level::Trace).unwrap();
        if !is_ledger_enabled() {
            warn!("Ledger test is disabled");
            return;
        }
        let mut manager = WManager::new(Some(ETC_DERIVATION_PATH.to_vec())).unwrap();
        manager.update(None).unwrap();

        assert!(!manager.devices().is_empty());

        let fd = &manager.devices()[0].1;

        let addresses = read_test_addresses();
        for address in addresses {
            let hdpath = HDPath::try_from(address.hdpath.as_str()).expect("Invalid HDPath");
            let act = manager.get_address(fd, Some(hdpath.to_bytes())).unwrap();
            assert_eq!(
                act,
                address.address
            );
        }
    }

    #[test]
    pub fn should_pick_hd_path() {
        if !is_ledger_enabled() {
            warn!("Ledger test is disabled");
            return;
        }
        let buf1 = vec![0];
        let buf2 = vec![1];

        let mut manager = WManager::new(Some(ETC_DERIVATION_PATH.to_vec())).unwrap();
        manager.update(None).unwrap();

        assert_eq!(manager.pick_hd_path(Some(buf1.clone())).unwrap(), buf1);

        manager.hd_path = Some(buf2.clone());
        assert_eq!(manager.pick_hd_path(Some(buf2.clone())).unwrap(), buf2);

        manager.hd_path = Some(buf1.clone());
        assert_eq!(manager.pick_hd_path(None).unwrap(), buf1);
    }

    #[test]
    pub fn should_parse_hd_path() {
        let path_str = "m/44'/60'/160720'/0/0";
        assert_eq!(
            ETC_DERIVATION_PATH[1..].to_vec(),
            path_to_arr(&path_str).unwrap()
        );
    }

    #[test]
    pub fn should_fail_parse_hd_path() {
        let mut path_str = "44'/60'/160720'/0/0";
        assert!(path_to_arr(&path_str).is_err());

        path_str = "44'/60'/16011_11111111111111111zz1111111111111111111111111111111'/0/0";
        assert!(path_to_arr(&path_str).is_err());
    }

    #[test]
    pub fn should_parse_hd_path_into_prefixed() {
        let path_str = "m/44'/60'/160720'/0/0";
        assert_eq!(
            ETC_DERIVATION_PATH.to_vec(),
            to_prefixed_path(&path_str).unwrap()
        );
    }
}
