//! # Serialize JSON RPC parameters

use super::core::{Address, Transaction};
use super::{align_bytes, to_arr, to_even_str, to_u64, trim_hex, Error, ToHex};
use hex::FromHex;
use jsonrpc_core::{Params, Value as JsonRpcValue};

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
        let gp_str = to_even_str(trim_hex(self.gas_price.as_str()));
        let v_str = to_even_str(trim_hex(self.value.as_str()));
        let gasl_str = to_even_str(trim_hex(self.gas.as_str()));

        let gas_limit = Vec::from_hex(gasl_str)?;
        let gas_price = Vec::from_hex(gp_str)?;
        let value = Vec::from_hex(v_str)?;
        let nonce = Vec::from_hex(to_even_str(trim_hex(self.nonce.as_str())))?;
        let data = to_even_str(trim_hex(self.data.as_str()));

        Ok(Transaction {
            nonce: to_u64(&nonce),
            gas_price: to_arr(&align_bytes(&gas_price, 32)),
            gas_limit: to_u64(&gas_limit),
            to: self.to.as_str().parse::<Address>().ok(),
            value: to_arr(&align_bytes(&value, 32)),
            data: Vec::from_hex(data)?,
        })
    }
}

impl Transaction {
    /// Signed transaction into raw data
    pub fn to_raw_params(signed_rlp: &[u8]) -> Params {
        let str = format!("0x{}", signed_rlp.to_hex());
        Params::Array(vec![JsonRpcValue::String(str)])
    }
}
