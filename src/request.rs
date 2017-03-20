use hyper::Url;
use hyper::client::IntoUrl;
use jsonrpc_core::{Value, Error};
use jsonrpc_core::futures::{BoxFuture, Future};

pub struct AsyncWrapper {
    pub url: Url,
}

impl AsyncWrapper {
    pub fn new<U: IntoUrl>(url: U) -> AsyncWrapper {
        AsyncWrapper { url: url.into_url().expect("Unexpected url encoding") }
    }

    pub fn request(&self, params: &::MethodParams) -> BoxFuture<Value, Error> {
        let client = ::reqwest::Client::new().expect("Error during create a client");

        let mut res = client.post(self.url.clone())
            .json(params)
            .send()
            .expect("Unable to get response object");

        let json: Value = res.json().expect("Unable to convert a response to JSON");

        ::futures::finished(json["result"].clone()).boxed()
    }
}
