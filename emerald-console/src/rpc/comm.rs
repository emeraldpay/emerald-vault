//! # Send JSON encoded HTTP requests

use cmd::Error;
use jsonrpc_core::Params;
use reqwest::{Client, Url};
use serde_json::Value;

lazy_static! {
    static ref CLIENT: Client = Client::builder()
        .build()
        .expect("Expect to create an HTTP client");
}

/// RPC methods
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ClientMethod {
    /// [eth_gasPrice](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gasprice)
    EthGasPrice,

    /// [eth_estimatePrice](
    /// https://github.com/ethereumproject/go-ethereum/wiki/JSON-RPC#eth_estimategas)
    EthEstimateGas,

    /// [eth_getTransactionCount](
    /// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gettransactioncount)
    EthGetTxCount,

    /// [eth_sendRawTransaction](
    /// https://github.com/paritytech/parity/wiki/JSONRPC-eth-module#eth_sendrawtransaction)
    EthSendRawTransaction,

    /// [eth_getBalance](
    /// https://github.com/ethereumproject/go-ethereum/wiki/JSON-RPC#eth_getbalance)
    EthGetBalance,
}

/// RPC method's parameters
#[derive(Clone, Debug, PartialEq)]
pub struct MethodParams<'a>(pub ClientMethod, pub &'a Params);

pub struct RpcConnector {
    pub url: Url,
}

impl RpcConnector {
    /// Send and JSON RPC HTTP post request
    pub fn send_post(&self, params: &MethodParams) -> Result<Value, Error> {
        let mut res = CLIENT.post(self.url.clone()).json(params).send()?;
        let json: Value = res.json()?;

        Ok(json["result"].clone())
    }
}
