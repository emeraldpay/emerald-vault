//! # Serialize JSON RPC parameters

use super::{Error, Method, MethodParams};
use super::core::{Address, PrivateKey, Transaction};
use jsonrpc_core::{Params, Value};
use rustc_serialize::hex::ToHex;
use serde::ser::{Serialize, Serializer};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

lazy_static! {
    static ref REQ_ID: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(1));
}

#[derive(Clone, Debug, Serialize)]
struct JsonData<'a> {
    jsonrpc: &'static str,
    method: &'static str,
    params: &'a Params,
    id: usize,
}

const EMPTY_DATA: &'static [u8; 1] = &[0];

impl<'a> Transaction<'a> {
    /// Try to convert a request parameters to `Transaction`.
    ///
    /// # Arguments
    ///
    /// * `p` - A request parameters (structure mapping directly to JSON)
    pub fn try_from(_p: &Params) -> Result<Transaction, Error> {
        Ok(Transaction {
               nonce: 0u64,
               gas_price: [0u8; 32],
               gas_limit: 0u64,
               from: Address::default(),
               to: Option::None,
               value: [0u8; 32],
               data: EMPTY_DATA,
           })
    }

    /// Sign transaction and return as raw data
    pub fn to_raw_params(&self, pk: &PrivateKey) -> Params {
        self.to_raw(pk)
            .map(|v| format!("0x{}", v.to_hex()))
            .map(|s| Params::Array(vec![Value::String(s)]))
            .expect("Expect to sign a transaction")
    }
}

impl<'a> Serialize for MethodParams<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        match self.0 {
            Method::ClientVersion => serialize("web3_clientVersion", self.1, s),
            Method::EthSyncing => serialize("eth_syncing", self.1, s),
            Method::EthBlockNumber => serialize("eth_blockNumber", self.1, s),
            Method::EthAccounts => serialize("eth_accounts", self.1, s),
            Method::EthGetBalance => serialize("eth_getBalance", self.1, s),
            Method::EthGetTxCount => serialize("eth_getTransactionCount", self.1, s),
            Method::EthSendRawTransaction => serialize("eth_sendRawTransaction", self.1, s),
            Method::EthCall => serialize("eth_call", self.1, s),
            Method::TraceCall => serialize("trace_call", self.1, s),
            Method::GetTxByHash => serialize("eth_getTransactionByHash", self.1, s),
        }
    }
}

fn serialize<S>(method: &'static str, params: &Params, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    to_json_data(method, params).serialize(serializer)
}

fn to_json_data<'a>(method: &'static str, params: &'a Params) -> JsonData<'a> {
    let id = REQ_ID.fetch_add(1, Ordering::SeqCst);

    JsonData {
        jsonrpc: "2.0",
        method: method,
        params: params,
        id: id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpc_core::Params;

    #[test]
    fn should_increase_request_ids() {
        assert_eq!(to_json_data("", &Params::None).id, 1);
        assert_eq!(to_json_data("", &Params::None).id, 2);
        assert_eq!(to_json_data("", &Params::None).id, 3);
    }
}
