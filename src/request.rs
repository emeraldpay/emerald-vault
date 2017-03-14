use jsonrpc_core::{Value, Error};
use jsonrpc_core::futures::{BoxFuture, Future};

pub struct StringWrapper {
    pub str: String,
}

pub struct Wrapper {
    pub url: StringWrapper,
}

impl Wrapper {
    pub fn request(&self, method: &::method::Method) -> BoxFuture<Value, Error> {
        let client = ::reqwest::Client::new().expect("Error during create a client");

        let mut res = client.post(&self.url.str)
            .json(method)
            .send()
            .expect("Unable to get response object");

        let json: Value = res.json().expect("Unable to convert a response to JSON");

        ::futures::finished(json["result"].clone()).boxed()
    }
}
