//! Rust middleware connector for ethereum classic blockchain (`EtherTRust`).

#![warn(missing_docs)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

extern crate reqwest;

extern crate serde;

#[macro_use]
extern crate serde_derive;

use serde::ser::{Serialize, Serializer};

static URL: &'static str = "http://127.0.0.1:8545";

enum Method {
    ClientVersion(),
}

impl Serialize for Method {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_some(&method())
    }
}

#[derive(Serialize, Debug)]
struct JsonData {
    jsonrpc: &'static str,
    method: &'static str,
    params: Vec<&'static str>,
    id: u32,
}

fn main() {
    let client = reqwest::Client::new().unwrap();

    let mut res = client.post(URL)
        .json(&Method::ClientVersion())
        .send()
        .unwrap();

    println!("Status: {}\n{}", res.status(), res.headers());

    ::std::io::copy(&mut res, &mut ::std::io::stdout()).unwrap();
}

fn method() -> JsonData {
    JsonData {
        jsonrpc: "2.0",
        method: "web3_clientVersion",
        params: vec![],
        id: 1,
    }
}

#[cfg(test)]
mod tests {

    use super::method;

    #[test]
    fn method_test() {
        assert_eq!(method().id, 1);
    }
}
