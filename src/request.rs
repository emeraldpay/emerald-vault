//! Send HTTP RPC requests

use hyper::Url;
use hyper::client::IntoUrl;
use jsonrpc_core::{Error, Value};
use jsonrpc_core::futures::{BoxFuture, Future};
use reqwest::Client;

pub struct AsyncWrapper {
    pub url: Url,
}

impl AsyncWrapper {
    pub fn new<U: IntoUrl>(url: U) -> AsyncWrapper {
        AsyncWrapper { url: url.into_url().expect("Expect to encode request url") }
    }

    pub fn request(&self, params: &::MethodParams) -> BoxFuture<Value, Error> {
        let client = Client::new().expect("Expect to create a request client");

        let mut res = client.post(self.url.clone())
            .json(params)
            .send()
            .expect("Expect to receive response");

        let json: Value = res.json().expect("Expect to deserialize a response as JSON");

        ::futures::finished(json["result"].clone()).boxed()
    }
}
