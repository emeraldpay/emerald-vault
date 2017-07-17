//! # Module to work with `HD Wallets`
//!
//! Currently supports only Ledger Nano S & Ledger Blue
//! `HD(Hierarchical Deterministic) Wallet` specified in
//! [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.medёiawiki)

mod error;
mod apdu;
mod hd_keystore;
mod comm;

use self::comm::sendrecv;
use self::apdu::{APDU_Builder, APDU};
use self::error::Error;
use super::{to_arr, Address, Transaction};
use u2fhid::{self, DeviceMap, Monitor, to_u8_array};
use uuid::Uuid;
use hidapi::{HidDeviceInfo, HidApi, HidDevice};
use std::{thread, time};
use std::str::{FromStr, from_utf8};


pub const GET_ETH_ADDRESS: u8 = 0x02;
pub const SIGN_ETH_TRANSACTION: u8 = 0x04;
pub const APDU_HEADER_SIZE: u8 = 0x05;
const ETC_DERIVATION_PATH: [u8; 21] =  [
    5,
    0x80, 0, 0, 44,
    0x80, 0, 0, 60,
    0x80, 0x02, 0x73, 0xd0,
    0x80, 0, 0, 0,
    0, 0, 0, 0
];  // 44'/60'/160720'/0'/0

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_PID: u16 = 0x0001; // for Nano S model


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

///
pub struct WManager {
    /// HID point used for communication
    hid: HidApi,
    /// List of available wallets
    devices: Vec<Device>,
    /// Derivation path
    hd_path: Vec<u8>,
}

impl WManager {
    /// Creates new `Wallet Manager` with a specified
    /// derivation path
    pub fn new(dpath: &[u8]) -> Result<WManager, Error> {
        let mut p: Vec<u8> = Vec::new();
        p.extend_from_slice(dpath);

        Ok(Self {
            hid: HidApi::new()?,
            devices: Vec::new(),
            hd_path: p,
        })
    }

    ///
    pub fn get_address(&self, fd: &str) -> Result<Address, Error> {
        let apdu = APDU_Builder::new(GET_ETH_ADDRESS)
            .with_data(&ETC_DERIVATION_PATH)
            .build();

        let handle = self.open(fd)?;
        let addr = sendrecv(&handle, &apdu)
            .and_then(|res| { match res.len() {
                    107 => Ok(res),
                    _ => Err(Error::HDWalletError("Address read returned invalid data length".to_string())),
                }
            })
            .and_then(|res: Vec<u8>| from_utf8(&res[67..107])
                .map(|ptr| ptr.to_string())
                .map_err(|e| Error::HDWalletError(format!("Can't parse address: {}", e.to_string()))))
            .and_then(|s| Address::from_str(&s)
                .map_err(|e| Error::HDWalletError(format!("Can't parse address: {}", e.to_string())))
            )?;

        Ok(addr)
    }

    /// Sign hash for transaction
    pub fn sign_transaction(&self, tr: Vec<u8>, fd: Option<String>) -> Result<Vec<u8>, Error> {
        unimplemented!();
    }

    ///
    pub fn devices(&self) -> DevicesList {
        self.devices.iter()
            .map(|d| (d.address.clone(), d.fd.clone()))
            .collect()
    }

    /// Update device list
    pub fn update(&mut self) -> Result<(), Error> {
        self.hid.refresh_devices();
        let mut new_devices = Vec::new();

        for hid_info in self.hid.devices() {
            if hid_info.product_id != LEDGER_PID || hid_info.vendor_id != LEDGER_VID  {
                continue;
            }
            let mut d = Device::from(hid_info);
            d.address = self.get_address(&d.fd)?;
            new_devices.push(d);
        }
        self.devices = new_devices;
        println!("Devices found {:?}", self.devices);

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
    use tests::*;
    use rustc_serialize::hex::ToHex;

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
        println!("RLP packed transaction: {:?}", &tx.hash(61));

    }

    #[test]
    pub fn should_get_address_with_ledger() {
        let mut manager = WManager::new(&ETC_DERIVATION_PATH).unwrap();
        manager.update().unwrap();
        let fd = &manager.devices()[0].1;

        println!("Address: {:?}", manager.get_address(fd).unwrap().to_hex());
    }
}
