use jsonrpc_core::{Value, Error};
use jsonrpc_core::futures::{BoxFuture, Future};

static NODE_URL: &'static str = "http://127.0.0.1:8546";

pub fn request(method: &::method::Method) -> BoxFuture<Value, Error> {
    let client = ::reqwest::Client::new().expect("Error during create a client");

    let mut res = client.post(NODE_URL)
        .json(method)
        .send()
        .expect("Unable to get response object");

    let json: Value = res.json().expect("Unable to convert a response to JSON");

    ::futures::finished(json["result"].clone()).boxed()
}
