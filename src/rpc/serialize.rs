//! # Serialize JSON RPC parameters

use super::{Error, Method, MethodParams};
use super::{align_bytes, to_arr, to_u64, ToHex};
use super::core::{Address, PrivateKey, Transaction};
use jsonrpc_core::{Params, Value};
use rustc_serialize::hex::FromHex;
use serde::ser::{Serialize, Serializer};
use serde_json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

lazy_static! {
    static ref REQ_ID: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(1));
}

fn empty_data() -> Option<String> {
    None
}

#[derive(Clone, Debug, Serialize)]
struct JsonData<'a> {
    jsonrpc: &'static str,
    method: &'static str,
    params: &'a Params,
    id: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SerializableTransaction {
    gasPrice: String,
    gas: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none", default="empty_data")]
    data: Option<String>,
}

impl IntoIterator for SerializableTransaction {
    type Item = String;
    type IntoIter = StrIntoIterator;

    fn into_iter(self) -> Self::IntoIter {
        StrIntoIterator { tr: self, index: 0 }
    }
}

struct StrIntoIterator {
    tr: SerializableTransaction,
    index: usize,
}

impl<'a> Iterator for StrIntoIterator {
    type Item = &'a str;
    fn next(&mut self) -> Option<&'a str> {
        let result = match self.index {
            0 => Some(self.tr.gasPrice.as_str()),
            1 => Some(self.tr.gas.as_str()),
            2 => Some(self.tr.to.unwrap_or(None).as_str()),
            3 => Some(self.tr.value.as_str()),
            4 => Some(self.tr.data.unwrap_or(None).as_str()),
            _ => return None,
        };
        self.index += 1;
        result
    }
}

impl From<Transaction> for SerializableTransaction {
    fn from(tr: Transaction) -> Self {
        Self {
            gasPrice: tr.gas_price.to_hex(),
            gas: tr.gas_limit.to_hex(),
            to: match tr.to {
                Some(a) => Some(a.to_hex()),
                _ => None
            },
            value: tr.value.to_hex(),
            data: match tr.data.is_empty() {
                true => None,
                false => Some(tr.data.to_hex()),
            },
        }
    }
}

impl Into<Transaction> for SerializableTransaction {
    fn into(self) -> Transaction {
        self.into_iter()
            .map(|v| {
                let (_, s) = v.split_at(2);
                v = s.to_string();
            });

        let gas_price = align_bytes(&self.gasPrice.from_hex().unwrap(), 32);
        let value = align_bytes(&self.value.from_hex().unwrap(), 32);

        Transaction {
            nonce: 0u64,
            gas_price: to_arr(&gas_price),
            gas_limit: to_u64(&self.gas.from_hex().unwrap()),
            to: match self.to {
                Some(s) => s.parse::<Address>().ok(),
                _ => None,
            },
            value: to_arr(&value),
            data: match self.data {
                Some(d) => d.from_hex().unwrap(),
                _ => Vec::new(),
            },
        }
    }
}

impl Transaction {
    ///
    pub fn try_from(p: &Params) -> Result<Transaction, Error> {
        let data = p.clone()
            .parse::<Value>().expect("Expect to parse params");
        let params = data.as_array().expect("Expect to parse Value");

        let str: SerializableTransaction  = serde_json::from_value(params[0].clone())?;
        Ok(str.into())
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
        println!("DEBUG: {:?}", tr.err());
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
