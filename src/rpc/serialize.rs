//! # Serialize JSON RPC parameters

use super::{Error, Method, MethodParams};
use super::{align_vec, to_arr};
use super::core::{Address, PrivateKey, Transaction};
use jsonrpc_core::{Params, Value};
use rustc_serialize::hex::{FromHex, ToHex};
use serde::ser::{Serialize, Serializer};
use std::collections::BTreeMap;
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
    pub fn try_from(p: &Params) -> Result<Transaction, Error> {
        let data = p.clone()
            .parse::<Value>()
            .expect("Expect to parse params");

        let params: BTreeMap<&str, &str> = data.get(0)
            .and_then(|d| d.as_object())
            .expect("Expect to extract JSON object")
            .iter()
            .map(|(k, v)| {
                     let (_, val) = v.as_str().expect("Expect to get parameter").split_at(2);
                     (k.as_str(), val)
                 })
            .collect();

        let extract = |name: &str| -> Result<Vec<u8>, Error> {
            let val = match params.get(name) {
                Some(p) => {
                    p.from_hex()
                        .map_err(|_| Error::DataFormat(format!("Can't extract '{}' field", name)))
                }
                None => return Err(Error::DataFormat(format!("no `{}` field", name))),
            };
            val
        };

        let gas_limit = match params.get("gas") {
            Some(p) => {
                u64::from_str_radix(p, 16)
                    .map_err(|_| { Error::DataFormat("Can't extract 'gas' field".to_string()) })
            }
            None => return Err(Error::DataFormat("no `gas` field".to_string())),
        };

        Ok(Transaction {
               nonce: 0u64,
               gas_price: to_arr(&align_vec(&extract(&"gasPrice")?, 32)),
               gas_limit: gas_limit?,
               to: Address::try_from(&extract(&"to")?).ok(),
               value: to_arr(&align_vec(&extract(&"value")?, 32)),
               data: EMPTY_DATA,
           })
    }

    /// Sign transaction and return as raw data
    pub fn to_raw_params(&self, pk: PrivateKey) -> Params {
        self.to_signed_raw(pk)
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
    use serde_json;

    #[test]
    fn should_increase_request_ids() {
        assert_eq!(to_json_data("", &Params::None).id, 1);
        assert_eq!(to_json_data("", &Params::None).id, 2);
        assert_eq!(to_json_data("", &Params::None).id, 3);
    }

    #[test]
    fn should_create_transaction() {
        let s = r#"[{"from": "0x2a191e0a15dbcfaf30fa0548ed189bc77f3284ae",
            "gas": "0x5208",
            "gasPrice": "0x2540be4000",
            "to": "0x004a301af857a471b9bde4fcc4654dba4f38272a",
            "value": "0xde0b6b3a764000"}]"#;
        let params: Params = serde_json::from_str(s).unwrap();
        let tr = Transaction::try_from(&params);
        assert!(tr.is_ok())
    }

    #[test]
    fn should_alert_missed_field() {
        let s = r#"[{"from": "0x2a191e0a15dbcfaf30fa0548ed189bc77f3284ae",
            "gas": "0x5208",
            "gasPrice": "0x2540be400",
            "to": "0x004a301af857a471b9bde4fcc4654dba4f38272a"}]"#;
        let p: Params = serde_json::from_str(s).unwrap();
        let tr = Transaction::try_from(&p);
        assert!(tr.is_err())
    }

    #[test]
    fn should_alert_invalid_field() {
        let s = r#"[{"from": "0x2a191e0a15dbcfaf30fa0548ed189bc77f3284ae",
            "gas": "0x5208",
            "gasPrice": "0x2540be400",
            "to": "0x004a301af857a471b9bde4fcc4654dba4f38272a",
            "valuuue": "0xde0b6b3a764000"}]"#;
        let p: Params = serde_json::from_str(s).unwrap();
        let tr = Transaction::try_from(&p);
        assert!(tr.is_err())
    }

    #[test]
    fn should_alert_invalid_data() {
        let s = r#"[{"from": "0xff",
            "gas": "0x5208",
            "gasPrice": "0x--",
            "to": "0x004a301af857a471b9bde4fcc4654dba4f38272a",
            "value": "0xde0b6b3a764000"}]"#;
        let p: Params = serde_json::from_str(s).unwrap();
        let tr = Transaction::try_from(&p);
        assert!(tr.is_err())
    }
}
