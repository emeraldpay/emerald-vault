//! # JSON RPC module

mod http;
mod serialize;
mod error;

use super::core::{Address, PrivateKey, Transaction};
use super::storage::{Storages, ChainStorage};
use super::Contracts;
use jsonrpc_core::{Error, ErrorCode, MetaIoHandler, Metadata, Params};
use jsonrpc_core::futures::Future;
use jsonrpc_minihttp_server::{DomainsValidation, Req, ServerBuilder, cors};
use log::LogLevel;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use futures;

/// RPC methods
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Method {
    /// [web3_clientVersion](https://github.com/ethereum/wiki/wiki/JSON-RPC#web3_clientversion)
    ClientVersion,
    /// [eth_syncing](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_syncing)
    EthSyncing,
    /// [eth_blockNumber](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_blocknumber)
    EthBlockNumber,
    /// [eth_accounts](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_accounts)
    EthAccounts,
    /// [eth_getBalance](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getbalance)
    EthGetBalance,
    /// [eth_getTransactionCount](
    /// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gettransactioncount)
    EthGetTxCount,
    /// [eth_sendTransaction](
    /// https://github.com/paritytech/parity/wiki/JSONRPC-eth-module#eth_sendtransaction)
    EthSendTransaction,
    /// [eth_sendRawTransaction](
    /// https://github.com/paritytech/parity/wiki/JSONRPC-eth-module#eth_sendrawtransaction)
    EthSendRawTransaction,
    /// [eth_call](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_call)
    EthCall,
    /// `trace_call`
    TraceCall,
    /// [eth_getTransactionByHash](
    /// https://github.com/ethereumproject/wiki/wiki/JSON-RPC#eth_gettransactionbyhash)
    GetTxByHash,
    /// [eth_getTransactionReceipt](
    /// https://github.com/ethereumproject/wiki/wiki/JSON-RPC#eth_gettransactionreceipt)
    GetTxReceipt,
}

/// RPC method's request metadata
#[derive(Clone, Debug)]
enum MethodMetadata {
    /// Nothing special
    None,
    /// Given account passphrase
    Passphrase(String),
}

impl MethodMetadata {
    fn with_authorization(str: &str) -> MethodMetadata {
        MethodMetadata::Passphrase(str.to_string())
    }
}

impl Default for MethodMetadata {
    fn default() -> Self {
        MethodMetadata::None
    }
}

impl Metadata for MethodMetadata {}

/// PRC method's parameters
#[derive(Clone, Debug, PartialEq)]
pub struct MethodParams<'a>(pub Method, pub &'a Params);

/// Start an HTTP RPC endpoint
pub fn start(addr: &SocketAddr, client_addr: &SocketAddr, base_path: Option<PathBuf>) {
    let mut io = MetaIoHandler::default();

    let url = Arc::new(http::AsyncWrapper::new(&format!("http://{}", client_addr)));

    {
        let url = url.clone();

        io.add_async_method("web3_clientVersion",
                            move |p| url.request(&MethodParams(Method::ClientVersion, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_syncing",
                            move |p| url.request(&MethodParams(Method::EthSyncing, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_blockNumber",
                            move |p| url.request(&MethodParams(Method::EthBlockNumber, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_accounts",
                            move |p| url.request(&MethodParams(Method::EthAccounts, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_getBalance",
                            move |p| url.request(&MethodParams(Method::EthGetBalance, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_getTransactionCount",
                            move |p| url.request(&MethodParams(Method::EthGetTxCount, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_getTransactionByHash",
                            move |p| url.request(&MethodParams(Method::GetTxByHash, &p)));
    }

    {
        let url = url.clone();

        io.add_method_with_meta("eth_sendTransaction", move |p, m| {
            if let MethodMetadata::Passphrase(ref _passphrase) = m {
                match Transaction::try_from(&p) {
                    Ok(tr) => {
                        url.request(&MethodParams(
                            Method::EthSendRawTransaction,
                            &Params::Array(tr.to_raw(&Default::default())?)))
                    }
                    Err(err) => futures::done(Err(Error::invalid_params(err.to_string()))).boxed(),
                }
            } else {
                futures::failed(Error::invalid_request()).boxed()
            }
        });
    }

    {
        let url = url.clone();

        io.add_async_method("eth_sendRawTransaction",
                            move |p| url.request(&MethodParams(Method::EthSendRawTransaction, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("eth_call",
                            move |p| url.request(&MethodParams(Method::EthCall, &p)));
    }

    {
        let url = url.clone();

        io.add_async_method("trace_call",
                            move |p| url.request(&MethodParams(Method::TraceCall, &p)));
    }

    let storage = match base_path {
        Some(p) => Storages::new(p),
        None => Storages::default(),
    };

    if storage.init().is_err() {
        panic!("Unable to initialize storage");
    }

    let chain = ChainStorage::new(&storage, "default".to_string());

    if chain.init().is_err() {
        panic!("Unable to initialize chain");
    }

    let dir = chain
        .get_path("contracts".to_string())
        .expect("Expect directory for contracts");

    let contracts = Arc::new(Contracts::new(dir));

    {
        let contracts = contracts.clone();

        io.add_async_method("emerald_contracts",
                            move |_| futures::finished(Value::Array(contracts.list())).boxed());
    }

    {
        let contracts = contracts.clone();

        io.add_async_method("emerald_addContract", move |p| match p {
            Params::Array(ref vec) => {
                match contracts.add(&vec[0]) {
                    Ok(_) => futures::finished(Value::Bool(true)).boxed(),
                    Err(_) => futures::failed(Error::new(ErrorCode::InternalError)).boxed(),
                }
            }
            _ => futures::failed(Error::new(ErrorCode::InvalidParams)).boxed(),
        });
    }

    let server = ServerBuilder::new(io)
        .meta_extractor(|req: &Req| {
                            req.header("Authorization")
                                .map(MethodMetadata::with_authorization)
                                .unwrap_or_default()
                        })
        .cors(DomainsValidation::AllowOnly(vec![cors::AccessControlAllowOrigin::Any,
                                                cors::AccessControlAllowOrigin::Null]))
        .start_http(addr)
        .expect("Expect to build HTTP RPC server");

    if log_enabled!(LogLevel::Info) {
        info!("Connector started on http://{}", server.address());
    }

    server.wait().expect("Expect to start HTTP RPC server");
}

#[cfg(test)]
mod tests {
    pub use super::*;
    pub use super::tests::*;
}
