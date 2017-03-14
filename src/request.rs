use jsonrpc_core::{Value, Error};
use jsonrpc_core::futures::{BoxFuture, Future};

pub struct AsyncWrapper {
    pub url: String,
}

impl AsyncWrapper {
    pub fn new(s: &str) -> AsyncWrapper {
        AsyncWrapper { url: s.to_string() }
    }

    pub fn request(&self, method: &::method::Method) -> BoxFuture<Value, Error> {
        let client = ::reqwest::Client::new().expect("Error during create a client");

        let mut res = client.post(&self.url)
            .json(method)
            .send()
            .expect("Unable to get response object");

        let json: Value = res.json().expect("Unable to convert a response to JSON");

        ::futures::finished(json["result"].clone()).boxed()
    }
}
