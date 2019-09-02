```shell

  _____                         _     _    _____                       _      
 |  ___|                       | |   | |  /  __ \                     | |     
 | |__ _ __ ___   ___ _ __ __ _| | __| |  | /  \/ ___  _ __  ___  ___ | | ___ 
 |  __| '_ ` _ \ / _ | '__/ _` | |/ _` |  | |    / _ \| '_ \/ __|/ _ \| |/ _ \
 | |__| | | | | |  __| | | (_| | | (_| |  | \__/| (_) | | | \__ | (_) | |  __/
 \____|_| |_| |_|\___|_|  \__,_|_|\__,_|  \____/ \___/|_| |_|___/\___/|_|\___|
                                                                             
                                                                             
```
[![Travis CI](https://travis-ci.org/emeraldpay/emerald-vault.svg?branch=master)](https://travis-ci.org/emeraldpay/emerald-vault)
[![Circle CI](https://circleci.com/gh/emeraldpay/emerald-vault/tree/master.svg?style=shield)](https://circleci.com/gh/emeraldpay/emerald-vault)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/e5nqu33xo8y4nk0v?svg=true)](https://ci.appveyor.com/project/emeraldpay/emerald-vault)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square&maxAge=2592000)

## About

Emerald Console is a tool to access Ethereum blockchain(s) from the command line. It connects to an 
external node (_"upstream"_) and allows a user or application to read information from the blockchain and to send new 
transactions. In the latter case it provides functionality to sign transactions by a provided Private Key. The tool 
integrates [emerald-vault](https://github.com/emeraldpay/emerald-vault) with the intention of generation, import, and/or 
storing of Ethereum Private Keys.

Emerald Console is compatible with:
 
 - Ethereum Classic ETC
 - Ethereum ETH
 - Rootstock
 - Ropsten Testnet
 - Morden Testnet
 - Rinkeby Testnet
 - Rootstock Testnet


## Usage

```shell
$ emerald-vault --help

emerald-vault
Command-line interface for Emerald platform

USAGE:
    emerald-vault [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -v               Sets the level of verbosity
    -V, --version    Display version

OPTIONS:
    -p, --base-path <base-path>    Set path for chain storage
    -c, --chain <chain>            Sets a chain name [default: etc-main]

SUBCOMMANDS:
    account        Account related commands
    balance        Request account's balance from ethereum node through RPC
    help           Prints this message or the help of the given subcommand(s)
    mnemonic       Create mnemonic phrase according to BIP39 spec
    server         Start local RPC server
    transaction    Transaction related commands

```

## Installing Emerald Vault

### Download stable binary

Binaries for all platforms are currently published at https://github.com/emeraldpay/emerald-vault/releases

### Download development build


Development builds are usually unstable and may contain critical issues that can lead to loss of funds. Use it on your risk


ETCDEV has a dedicated website for all build artifacts, which are published on each new commit into `master` branch.
To download a latest development build, please open https://builds.etcdevteam.com and choose _Emerald CLI_ tab


### Build from sources

#### Requirements

Install Rust from https://www.rust-lang.org/en-US/install.html


Unix one-liner:
```
curl https://sh.rustup.rs -sSf | sh
```

On Windows, Rust additionally requires the C++ build tools for Visual Studio 2013 or later. The easiest way to acquire
the build tools is by installing Microsoft Visual C++ Build Tools 2017 which provides just the Visual C++ build tools.

#### Compile

```
git clone https://github.com/emeraldpay/emerald-vault.git
cd emerald-rs
cargo build --release
cd target\debug
```

## Links

- Issues: https://github.com/emeraldpay/emerald-vault/issues
- Development binaries: http://builds.etcdevteam.com/


## License

Apache 2.0

