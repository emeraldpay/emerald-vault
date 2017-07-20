//! # Module to work with `HD Wallets`
//!
//! Currently supports only Ledger Nano S & Ledger Blue
//! `HD(Hierarchical Deterministic) Wallet` specified in
//! [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.medёiawiki)

mod error;
mod apdu;
mod keystore;
mod comm;

use self::apdu::ApduBuilder;
use self::comm::sendrecv;
pub use self::error::Error;
pub use self::keystore::HdwalletCrypto;
use super::{Address, ECDSA_SIGNATURE_BYTES, Signature, to_arr, to_bytes};
use hidapi::{HidApi, HidDevice, HidDeviceInfo};
use std::{thread, time};
use std::str::{FromStr, from_utf8};


const GET_ETH_ADDRESS: u8 = 0x02;
const SIGN_ETH_TRANSACTION: u8 = 0x04;
const CHUNK_SIZE: usize = 255;

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_PID: u16 = 0x0001; // for Nano S model
const DERIVATION_INDEX_SIZE: usize = 4;
#[allow(dead_code)]
pub const ETC_DERIVATION_PATH: [u8; 21] = [
    5,
    0x80,
    0,
    0,
    44,
    0x80,
    0,
    0,
    60,
    0x80,
    0x02,
    0x73,
    0xd0,
    0x80,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
]; // 44'/60'/160720'/0'/0


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

/// Parse HD path into byte array
pub fn path_to_arr(hd_str: &str) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();

    hd_str
        .split("/")
        .map(|s| {
            let mut str = s.to_string();
            let mut v: u64 = 0;

            if str.ends_with("'") {
                v += 0x80000000;
                str.remove(s.len() - 1);
            }
            match str.parse::<u32>() {
                Ok(d) => v += d as u64,
                Err(_) => {
                    return Err(Error::HDWalletError(
                        format!("Invalid `hd_path` format: {}", hd_str),
                    ))
                }
            }
            buf.extend(to_bytes(v, 4));
            Ok(())
        })
        .collect::<Vec<_>>();

    Ok(buf)
}

/// Parse HD path into byte array
/// prefixed with count of derivation indexes
pub fn to_prefixed_path(hd_str: &str) -> Result<Vec<u8>, Error> {
    let v = path_to_arr(hd_str)?;
    let count = (v.len() % DERIVATION_INDEX_SIZE) as u8;
    let mut buf = Vec::with_capacity(v.len() + 1);

    buf.push(count);
    buf.extend(v);

    Ok(buf)
}

///
pub struct WManager {
    /// HID point used for communication
    hid: HidApi,
    /// List of available wallets
    devices: Vec<Device>,
    /// Derivation path
    hd_path: Option<Vec<u8>>,
}

impl WManager {
    /// Creates new `Wallet Manager` with a specified
    /// derivation path
    pub fn new(hd_path: Option<&[u8]>) -> Result<WManager, Error> {
        let p = match hd_path {
            Some(p) => {
                let mut buf = Vec::new();
                buf.extend_from_slice(p);
                Some(buf)
            }
            _ => None,
        };

        Ok(Self {
            hid: HidApi::new()?,
            devices: Vec::new(),
            hd_path: p,
        })
    }

    /// Decides what HD path to use
    fn pick_hd_path(&self, h: Option<Vec<u8>>) -> Result<Vec<u8>, Error> {
        if self.hd_path.is_none() && h.is_none() {
            return Err(Error::HDWalletError("HD path is not specified".to_string()));
        }

        Ok(h.or(self.hd_path.clone()).unwrap())
    }

    ///
    pub fn get_address(&self, fd: &str, hd_path: Option<Vec<u8>>) -> Result<Address, Error> {
        let hd_path = self.pick_hd_path(hd_path)?;

        let apdu = ApduBuilder::new(GET_ETH_ADDRESS)
            .with_data(&hd_path)
            .build();

        let handle = self.open(fd)?;
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

    /// Sign hash for transaction
    ///
    /// # Arguments:
    /// fd - file descritptor to corresponding HID device
    /// tr - RLP packed transaction
    /// hd_path - optinal HD path, prefixed with count of derivation indexes
    pub fn sign_transaction(
        &self,
        fd: &str,
        tr: &[u8],
        hd_path: Option<Vec<u8>>,
    ) -> Result<Signature, Error> {;
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

        let handle = self.open(fd)?;
        let mut res = sendrecv(&handle, &init_apdu)?;

        for chunk in cont.chunks(CHUNK_SIZE) {
            let apdu_cont = ApduBuilder::new(SIGN_ETH_TRANSACTION)
                .with_p1(0x80)
                .with_data(chunk)
                .build();
            res = sendrecv(&handle, &apdu_cont)?;
        }

        match res.len() {
            ECDSA_SIGNATURE_BYTES => {
                let mut val: [u8; ECDSA_SIGNATURE_BYTES] = [0; ECDSA_SIGNATURE_BYTES];
                val.copy_from_slice(&res);
                Ok(Signature::from(val))
            }
            v => Err(Error::HDWalletError(format!(
                "Invalid signature length. Expected: {}, received: {}",
                ECDSA_SIGNATURE_BYTES,
                v
            ))),
        }
    }

    /// List all available devices
    pub fn devices(&self) -> DevicesList {
        self.devices
            .iter()
            .map(|d| (d.address.clone(), d.fd.clone()))
            .collect()
    }

    /// Update device list
    pub fn update(&mut self, hd_path: Option<Vec<u8>>) -> Result<(), Error> {
        let hd_path = self.pick_hd_path(hd_path)?;

        self.hid.refresh_devices();
        let mut new_devices = Vec::new();

        for hid_info in self.hid.devices() {
            if hid_info.product_id != LEDGER_PID || hid_info.vendor_id != LEDGER_VID {
                continue;
            }
            let mut d = Device::from(hid_info);
            d.address = self.get_address(&d.fd, Some(hd_path.clone()))?;
            new_devices.push(d);
        }
        self.devices = new_devices;
        debug!("Devices found {:?}", self.devices);

        Ok(())
    }

    fn open(&self, path: &str) -> Result<HidDevice, Error> {
        for _ in 0..5 {
            match self.hid.open_path(&path) {
                Ok(h) => return Ok(h),
                Err(_) => (),
            }
            thread::sleep(time::Duration::from_millis(100));
        }

        Err(Error::HDWalletError(format!("Can't open path: {}", path)))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use core::Transaction;
    use rustc_serialize::hex::ToHex;
    use tests::*;

    #[test]
    pub fn should_sign_with_ledger() {
        let mut manager = WManager::new(Some(&ETC_DERIVATION_PATH)).unwrap();
        manager.update(None).unwrap();

        if manager.devices().is_empty() {
            // No device connected, skip test
            return;
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
            data: Vec::new(),
        };

        let rlp = tx.to_rlp();
        let fd = &manager.devices()[0].1;
        let sign = manager.sign_transaction(&fd, &rlp, None);

        assert!(sign.is_ok());
        println!("Signature: {:?}", &sign.unwrap());
    }

    #[test]
    #[ignore]
    pub fn should_get_address_with_ledger() {
        let mut manager = WManager::new(Some(&ETC_DERIVATION_PATH)).unwrap();
        manager.update(None).unwrap();

        if manager.devices().is_empty() {
            // No device connected, skip test
            return;
        }

        let fd = &manager.devices()[0].1;
        let addr = manager.get_address(fd, None).unwrap();

        assert_eq!("78296f1058dd49c5d6500855f59094f0a2876397", addr.to_hex());
    }

    #[test]
    #[ignore]
    pub fn should_pick_hd_path() {
        let buf1 = vec![0];
        let buf2 = vec![1];

        let mut manager = WManager::new(None).unwrap();
        assert_eq!(manager.pick_hd_path(Some(buf1.clone())).unwrap(), buf1);

        manager.hd_path = Some(buf2.clone());
        assert_eq!(manager.pick_hd_path(Some(buf2.clone())).unwrap(), buf2);

        manager.hd_path = Some(buf1.clone());
        assert_eq!(manager.pick_hd_path(None).unwrap(), buf1);
    }

    #[test]
    pub fn should_parse_hd_path() {
        let path_str = "44\'/60\'/160720\'/0\'/0";
        assert_eq!(
            ETC_DERIVATION_PATH[1..].to_vec(),
            path_to_arr(&path_str).unwrap()
        );
    }

    #[test]
    pub fn should_fail_parse_hd_path() {
        let path_str = "44\'/60\'/160AAAA0\'/0\'/0";
        assert!(path_to_arr(&path_str).is_err());

        let path_str = "44\'/60\'/16011111111111111111111111111111111111111111111111111111\'/0\'/0";
        assert!(path_to_arr(&path_str).is_err());
    }

    #[test]
    pub fn should_parse_hd_path_prefixed() {
        let path_str = "44\'/60\'/160720\'/0\'/0";
        assert_eq!(
            ETC_DERIVATION_PATH.to_vec(),
            to_prefixed_path(&path_str).unwrap()
        );;
    }
}
