//! # Send JSON encoded HTTP requests

use super::{Error, MethodParams};
use hyper::Url;
use hyper::client::IntoUrl;
use jsonrpc_core::Error as JsonRpcError;
use jsonrpc_core::futures::{BoxFuture, Future};
use reqwest::Client;
use serde_json;

lazy_static! {
    static ref CLIENT: Client = Client::new().expect("Expect to create an HTTP client");
}

pub struct AsyncWrapper {
    pub url: Url,
}

impl AsyncWrapper {
    pub fn new<U: IntoUrl>(url: U) -> AsyncWrapper {
        AsyncWrapper { url: url.into_url().expect("Expect to encode request url") }
    }

    /// Wrap JSON RPC HTTP post request with async futures
    pub fn request(&self, params: &MethodParams) -> BoxFuture<serde_json::Value, JsonRpcError> {
        match self.send_post(params) {
            Ok(res) => ::futures::finished(res).boxed(),
            Err(err) => {
                error!("HTTP POST request error: {}", err);
                ::futures::failed(err.into()).boxed()
            }
        }
    }

    /// Send and JSON RPC HTTP post request
    pub fn send_post(&self, params: &MethodParams) -> Result<serde_json::Value, Error> {
        let mut res = CLIENT.post(self.url.clone()).json(params).send()?;
        let json = res.json()?;
        Ok(json["result"].clone())
    }
}
