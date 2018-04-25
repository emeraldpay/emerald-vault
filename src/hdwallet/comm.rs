//! # Module providing commnication using HID API
//!

use super::apdu::APDU;
use super::error::Error;
use super::to_arr;
use super::HidDevice;
use log;
use std::cmp::min;
use std::mem::size_of_val;
use std::slice;

///
pub const HID_RPT_SIZE: usize = 64;

///
pub const INIT_HEADER_SIZE: usize = 7;

/// Size of data chunk expected in Init USB HID Packets
const INIT_DATA_SIZE: usize = HID_RPT_SIZE - 12;

/// Size of data chunk expected in Cont USB HID Packets
const CONT_DATA_SIZE: usize = HID_RPT_SIZE - 5;

/// ISO 7816-4 defined response status words
pub const SW_NO_ERROR: [u8; 2] = [0x90, 0x00];
pub const SW_CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];
pub const SW_WRONG_DATA: [u8; 2] = [0x6A, 0x80];
pub const SW_WRONG_LENGTH: [u8; 2] = [0x67, 0x00];
pub const SW_INCORRECT_PARAMETERS: [u8; 2] = [0x6b, 0x00];
pub const SW_USER_CANCEL: [u8; 2] = [0x6A, 0x85];

/// Packs header with Ledgers magic numbers
/// For more details refer APDU doc:
/// <https://github.com/LedgerHQ/blue-app-eth/blob/master/doc/ethapp.asc#general-purpose-apdus>
///
fn get_hid_header(index: usize) -> [u8; 5] {
    [0x01, 0x01, 0x05, (index >> 8) as u8, (index & 0xff) as u8]
}

///
fn check_recv_frame(frame: &[u8], index: usize) -> Result<(), Error> {
    if size_of_val(frame) < 5 || frame[0] != 0x01 || frame[1] != 0x01 || frame[2] != 0x05 {
        return Err(Error::CommError("Invalid frame header size".to_string()));
    }

    let seq = (frame[3] as usize) << 8 | (frame[4] as usize);
    if seq != index {
        return Err(Error::CommError("Invalid frame size".to_string()));
    }

    if index == 0 && size_of_val(frame) < 7 {
        return Err(Error::CommError("Invalid frame size".to_string()));
    }

    Ok(())
}

fn get_init_header(apdu: &APDU) -> [u8; INIT_HEADER_SIZE] {
    let mut buf = Vec::with_capacity(INIT_HEADER_SIZE);
    buf.extend_from_slice(&[(apdu.len() >> 8) as u8, (apdu.len() & 0xff) as u8]);
    buf.extend_from_slice(&apdu.raw_header());
    to_arr(&buf)
}

fn set_data(data: &mut [u8], itr: &mut slice::Iter<u8>, max: usize) {
    let available = itr.size_hint().0;

    for i in 0..min(max, available) {
        data[i] = *itr.next().unwrap();
    }
}

/// Check `status word`, if invalid coverts it
/// to the proper error message
fn sw_to_error(sw_h: u8, sw_l: u8) -> Result<(), Error> {
    match [sw_l, sw_h] {
        SW_NO_ERROR => Ok(()),
        SW_WRONG_LENGTH => Err(Error::CommError("Incorrect length".to_string())),
        SW_WRONG_DATA => Err(Error::CommError("Invalid data".to_string())),
        SW_INCORRECT_PARAMETERS => Err(Error::CommError("Incorrect parameters".to_string())),
        SW_USER_CANCEL => Err(Error::CommError("Canceled by user".to_string())),
        SW_CONDITIONS_NOT_SATISFIED => {
            Err(Error::CommError("Conditions not satisfied()".to_string()))
        }
        v => Err(Error::CommError(format!(
            "Internal communication error: {:?}",
            v
        ))),
    }
}

///
pub fn sendrecv(dev: &HidDevice, apdu: &APDU) -> Result<Vec<u8>, Error> {
    let mut frame_index: usize = 0;
    let mut data_itr = apdu.data.iter();
    let mut init_sent = false;

    debug!(">> senrecv input: {:?}", &apdu);
    // Write Data.
    while data_itr.size_hint().0 != 0 {
        // Add 1 to HID_RPT_SIZE since we need to prefix this with a record
        // index.
        let mut frame: [u8; (HID_RPT_SIZE + 1) as usize] = [0; (HID_RPT_SIZE + 1) as usize];

        frame[1..6].clone_from_slice(&get_hid_header(frame_index));
        if !init_sent {
            frame[6..13].clone_from_slice(&get_init_header(apdu));
            init_sent = true;
            set_data(&mut frame[13..], &mut data_itr, INIT_DATA_SIZE);
        } else {
            set_data(&mut frame[6..], &mut data_itr, CONT_DATA_SIZE);
        }

        if log_enabled!(log::LogLevel::Trace) {
            let parts: Vec<String> = frame.iter().map(|byte| format!("{:02x}", byte)).collect();
            trace!(">> USB send: {}", parts.join(""));
        }

        if let Err(err) = dev.write(&frame) {
            return Err(err.into());
        };
        frame_index += 1;
    }

    debug!("\t |- read response");
    frame_index = 0;
    let mut data: Vec<u8> = Vec::new();
    let datalen: usize;
    let mut recvlen: usize = 0;
    let mut frame: [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];
    let frame_size = dev.read(&mut frame)?;

    check_recv_frame(&frame, frame_index)?;
    datalen = (frame[5] as usize) << 8 | (frame[6] as usize);
    data.extend_from_slice(&frame[7..frame_size]);

    recvlen += frame_size;
    frame_index += 1;
    debug!(
        "\t\t|-- init data: {:?}, recvlen: {}, datalen: {}",
        data, recvlen, datalen
    );

    while recvlen < datalen {
        frame = [0u8; HID_RPT_SIZE];
        let frame_size = dev.read(&mut frame)?;

        check_recv_frame(&frame, frame_index)?;
        data.extend_from_slice(&frame[5..frame_size]);
        recvlen += frame_size;
        frame_index += 1;
        debug!(
            "\t\t|-- cont_{:?} size:{:?}, data: {:?}",
            frame_index,
            data.len(),
            data
        );
    }
    data.truncate(datalen);
    match sw_to_error(data.pop().unwrap(), data.pop().unwrap()) {
        Ok(_) => Ok(data),
        Err(e) => Err(e),
    }
}
