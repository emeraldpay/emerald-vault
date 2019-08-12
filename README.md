# Emerald-rs - Rust library to operate Ethereum blockchains

[![Travis CI](https://travis-ci.org/ETCDEVTeam/emerald-rs.svg?branch=master)](https://travis-ci.org/ETCDEVTeam/emerald-rs)
[![Circle CI](https://circleci.com/gh/ETCDEVTeam/emerald-rs/tree/master.svg?style=shield)](https://circleci.com/gh/etcdevteam/emerald-rs)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/er3wb073udepk3bl/branch/master?svg=true)](https://ci.appveyor.com/project/etcdevteam/emerald-rs)
![Coveralls](https://coveralls.io/repos/github/ethereumproject/emerald-rs/badge.svg)
[![Crates](https://img.shields.io/crates/v/emerald-rs.svg?style=flat-square)](https://crates.io/crates/emerald-rs)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square&maxAge=2592000)


```
NOTE:

An offline wallet, also known as cold storage, provides the highest level of security for savings.
It involves storing a wallet in a secured place that is not connected to the network (air-gapped).
When done properly, it can offer a very good protection against computer vulnerabilities.
```

Distributed as a Rust crate or can be embedded via foreign function interface (FFI).

For minimalistic CLI tool refer to [Emerald Console](emerald-cli/), or 
if you looking for a fully-featured UI wallet, take a look at our [Emerald Wallet](https://emeraldwallet.io)


## Features

### General

* Create and read Private Keys
* Compatible with Parity and Geth private key JSON files
* Import Private Key from Mnemonic Phrase
* Support of Ledger Nano hardware wallet 
* Transactions signing

## Installation

Ensure you have these dependencies installed:

```
openssl pkgconfig rustc cargo clang
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
 
## Contact
 Chat with us via [Gitter](https://gitter.im/etcdev-public/Lobby)

## License

Copyright 2019 ETCDEV GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
