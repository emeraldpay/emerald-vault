//! # Serialize JSON RPC parameters

use super::{Error, ToHex, align_bytes, to_arr, to_u64, trim_hex};
use super::core::{Address, PrivateKey, Transaction};
use jsonrpc_core::{Params, Value as JValue};
use rustc_serialize::hex::FromHex;
use serde::{Serialize, Serializer};
use serde_json::{self, Value};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Deserialize, Debug)]
pub struct RPCTransaction {
    pub from: String,
    pub to: String,
    pub gas: String,
    #[serde(rename = "gasPrice")]
    pub gas_price: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub data: String,
    pub nonce: String,
}

impl RPCTransaction {
    pub fn try_into(self) -> Result<Transaction, Error> {
        let gp_str = trim_hex(self.gas_price.as_str());
        let v_str = trim_hex(self.value.as_str());

        let gas_limit = trim_hex(self.gas.as_str()).from_hex()?;
        let gas_price = gp_str.from_hex()?;
        let value = v_str.from_hex()?;
        let nonce = trim_hex(self.nonce.as_str()).from_hex()?;

        Ok(Transaction {
               nonce: to_u64(&nonce),
               gas_price: to_arr(&align_bytes(&gas_price, 32)),
               gas_limit: to_u64(&gas_limit),
               to: self.to.as_str().parse::<Address>().ok(),
               value: to_arr(&align_bytes(&value, 32)),
               data: trim_hex(self.data.as_str()).from_hex()?,
           })
    }
}

impl Transaction {
    /// Sign transaction and return as raw data
    pub fn to_raw_params(&self, pk: PrivateKey, chain: u8) -> Params {
        self.to_signed_raw(pk, chain)
            .map(|v| format!("0x{}", v.to_hex()))
            .map(|s| Params::Array(vec![JValue::String(s)]))
            .expect("Expect to sign a transaction")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpc_core::Params;
    use serde_json;
    use std::str::FromStr;
}
