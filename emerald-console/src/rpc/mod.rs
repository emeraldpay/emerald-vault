//! # JSON RPC module

mod comm;
mod serialize;

pub use self::comm::{ClientMethod, MethodParams, RpcConnector};
use cmd::Error;
use emerald::Address;
use hex::ToHex;
use jsonrpc_core::{Params, Value};

/// Get nonce for address from remote node
///
/// # Arguments:
///
/// * addr - target address
///
pub fn request_nonce(rpc: &RpcConnector, addr: &Address) -> Result<String, Error> {
    let data = vec![
        Value::String(addr.to_string()),
        Value::String("latest".to_string()),
    ];
    let params = Params::Array(data);
    let val = rpc.send_post(&MethodParams(ClientMethod::EthGetTxCount, &params))?;

    match val.as_str() {
        Some(s) => Ok(s.to_string()),
        None => Err(Error::ExecError("Can't parse tx count".to_string())),
    }
}

/// Get balance for selected account
///
/// # Arguments:
///
/// * rpc -
/// * addr - target account
///
/// # Return:
///
/// * String - latest balance
///
pub fn request_balance(rpc: &RpcConnector, addr: &Address) -> Result<String, Error> {
    let data = vec![
        Value::String(addr.to_string()),
        Value::String("latest".to_string()),
    ];

    let params = Params::Array(data);
    rpc.send_post(&MethodParams(ClientMethod::EthGetBalance, &params))
        .and_then(|v| match v.as_str() {
            Some(str) => Ok(str.to_string()),
            None => Err(Error::ExecError(format!("Can't get balance for {}", addr))),
        })
}

/// Get estimated gas from remote node
///
/// # Arguments:
///
/// * rpc -
///
pub fn request_gas(rpc: &RpcConnector) -> Result<String, Error> {
    let data = vec![Value::String("latest".to_string())];
    let params = Params::Array(data);
    let val = rpc.send_post(&MethodParams(ClientMethod::EthEstimateGas, &params))?;

    match val.as_str() {
        Some(s) => Ok(s.to_string()),
        None => Err(Error::ExecError("Can't estimate required gas".to_string())),
    }
}

/// Get gas price from remote node
///
/// # Arguments:
///
/// * rpc -
///
pub fn request_gas_price(rpc: &RpcConnector) -> Result<String, Error> {
    let params = Params::Array(vec![]);
    let val = rpc.send_post(&MethodParams(ClientMethod::EthGasPrice, &params))?;

    match val.as_str() {
        Some(s) => Ok(s.to_string()),
        None => Err(Error::ExecError("Can't estimate gas price".to_string())),
    }
}

/// Send signed raw transaction to the remote client
///
/// # Arguments:
///
/// * raw - signed tx
///
/// # Return:
///
/// * String - transaction hash
///
pub fn send_transaction(rpc: &RpcConnector, raw: &[u8]) -> Result<String, Error> {
    let data = vec![Value::String(format!("0x{}", &raw.to_hex()))];
    let params = Params::Array(data);
    rpc.send_post(&MethodParams(ClientMethod::EthSendRawTransaction, &params))
        .and_then(|v| match v.as_str() {
            Some(str) => Ok(str.to_string()),
            None => Err(Error::ExecError("Can't parse tx hash".to_string())),
        })
}
