<p align="center">
  <h2 align="center">Emerald Vault</a></h3>
  <p align="center">Secure account management for Ethereum Classic</a></p>
  <p align="center">
    <a href="https://travis-ci.org/ethereumproject/emerald-rs"><img alt="Travis" src="https://img.shields.io/travis/ethereumproject/emerald-rs/master.svg?style=flat-square"></a>
    <a href="https://ci.appveyor.com/project/splix/emerald-rs"><img alt="AppVeyor" src="https://img.shields.io/appveyor/ci/splix/emerald-rs/master.svg?style=flat-square"></a>
    <a href="https://crates.io/crates/emerald-rs"><img alt="crates.io" src="https://img.shields.io/crates/v/emerald-rs.svg?style=flat-square"></a>
    <a href='https://coveralls.io/github/ethereumproject/emerald-rs'><img src='https://coveralls.io/repos/github/ethereumproject/emerald-rs/badge.svg' alt='Coverage Status' /></a>
    <a href="LICENSE"><img alt="Software License" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square&maxAge=2592000"></a>
  </p>
</p>

---



```
NOTE:

An offline wallet, also known as cold storage, provides the highest level of security for savings.
It involves storing a wallet in a secured place that is not connected to the network (air-gapped).
When done properly, it can offer a very good protection against computer vulnerabilities.
```

Distributed as a Rust crate or can be embedded via foreign function interface (FFI).

For minimalistic CLI tool refer to [Emerald-cli](https://github.com/ethereumproject/emerald-cli), or if you looking for a fully-featured UI online wallet, take a look at our [Ethereum Classic Emerald Wallet](https://github.com/ethereumproject/emerald-wallet)

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

Should your distribution or operating system not have a recent `cargo` and `rustc` binaries, you can install them from: http://doc.crates.io/

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

 [JSON-RPC API](docs/api.md)
 
 # Contact
 Chat with us via [Gitter](https://gitter.im/ethereumproject/emerald-wallet)

## License

Apache 2.0
