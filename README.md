:rootdir: .
:icons: font
:imagesdir: {rootdir}/images

ifdef::env-github,env-browser[:badges:]
ifdef::env-github,env-browser[:outfilesuffix: .adoc]

ifndef::badges[]
= Emerald-rs
endif::[]

ifdef::badges[]
= Emerald-rs image:https://img.shields.io/travis/ethereumproject/emerald-rs/master.svg?style=flat-square["Build Status", link="https://travis-ci.org/ethereumproject/emerald-rs"] image:https://img.shields.io/appveyor/ci/dulanov/emerald-rs/master.svg?style=flat-square["Build Status", link="https://ci.appveyor.com/project/dulanov/emerald-rs"] image:https://img.shields.io/crates/v/emerald-cli.svg?style=flat-square["Crates", link="https://crates.io/crates/emerald-cli"] image:https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square&maxAge=2592000["License", link="https://github.com/ethereumproject/emerald-rs/blob/master/LICENSE"]
endif::[]

Secure account management for Ethereum Classic.

[NOTE]
```
An offline wallet, also known as cold storage, provides the highest level of security for savings.
It involves storing a wallet in a secured place that is not connected to the network (air-gapped).
When done properly, it can offer a very good protection against computer vulnerabilities.
```

Distributed as a Rust crate or can be embedded via foreign function interface (FFI).

For minimalistic CLI tool refer to [emerald-cli](https://github.com/ethereumproject/emerald-cli), or if you looking for a fully-featured UI online wallet, take a look at our [Ethereum Classic Emerald Wallet](https://github.com/ethereumproject/emerald-wallet)

Developed by [ETCDEV Team](http://www.etcdevteam.com/)

## Features

### General

* [x] Accounts
* [x] Transactions signing
* [x] Smart contracts (ABI)
* [ ] C interface (ABI)

## Installation

Ensure you have these dependencies installed:

```
openssl pkgconfig rustc cargo
```

`cargo` and `rustc` should be at least versions 0.18 and 1.17 respectively.

Should your distribution or operating system not have a recent cargo and rustc binaries you can install them from: http://doc.crates.io/.

```
$ cargo install emerald-cli
```

If you use [Nix](http://nixos.org/nix) you may execute the `nix-shell` command in your cloned repository and all dependencies will be made available in your environment automatically.

## Examples

```
extern crate emerald_core as emerald;

use std::net::SocketAddr;

fn main() {
    let addr = "127.0.0.1:1920"
        .parse::<SocketAddr>()
        .expect("Expect to parse address");

    emerald::start(&addr, None, None);
}
```

## References

 [JSON-RPC API](docs/api.adoc)

## License

Apache 2.0
