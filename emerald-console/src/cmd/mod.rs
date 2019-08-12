//! # Execute command

mod account;
mod error;
mod transaction;
#[macro_use]
mod arg_handlers;

use self::account::account_cmd;
pub use self::arg_handlers::*;
pub use self::error::Error;
use self::transaction::transaction_cmd;
use super::emerald::keystore::{KdfDepthLevel, KeyFile};
use super::emerald::mnemonic::{gen_entropy, Language, Mnemonic, ENTROPY_BYTE_LENGTH};
use super::emerald::storage::{default_path, KeyfileStorage, StorageController};
use super::emerald::PrivateKey;
use super::emerald::{self, align_bytes, to_arr, to_even_str, trim_hex, Address, Transaction};
use clap::ArgMatches;
use rpc;
use std::net::SocketAddr;
use std::path::PathBuf;

type ExecResult = Result<(), Error>;

const DEFAULT_CHAIN_NAME: &str = "mainnet";
const DEFAULT_UPSTREAM: &str = "127.0.0.1:8545";

/// Create new command executor
pub fn execute(matches: &ArgMatches) -> ExecResult {
    let env = EnvVars::parse();

    let chain = matches.value_of("chain").unwrap_or(DEFAULT_CHAIN_NAME);
    info!("Chain name: {}", DEFAULT_CHAIN_NAME);

    let mut base_path = PathBuf::new();
    if let Some(p) = matches
        .value_of("base-path")
        .or_else(|| env.emerald_base_path.as_ref().map(String::as_str))
    {
        base_path.push(&p)
    } else {
        base_path = default_path();
    }

    let storage_ctrl = StorageController::new(base_path)?;

    match matches.subcommand() {
        ("server", Some(sub_m)) => server_cmd(sub_m, storage_ctrl),
        ("account", Some(sub_m)) => account_cmd(sub_m, storage_ctrl.get_keystore(chain)?, &env),
        ("transaction", Some(sub_m)) => {
            transaction_cmd(sub_m, storage_ctrl.get_keystore(chain)?, &env, chain)
        }
        ("balance", Some(sub_m)) => balance_cmd(sub_m),
        ("mnemonic", Some(_)) => mnemonic_cmd(),
        ("nonce", Some(sub_m)) => nonce_cmd(sub_m),
        _ => Err(Error::ExecError(
            "No command selected. Use `-h` for help".to_string(),
        )),
    }
}

/// Launch connector in a `server` mode
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
/// * chain - chain name
///
fn server_cmd(matches: &ArgMatches, storage_ctrl: StorageController) -> ExecResult {
    info!("Starting Emerald Vault - v{}", emerald::version());
    let host = matches.value_of("host").unwrap_or_default();
    let port = matches.value_of("port").unwrap_or_default();
    let addr = format!("{}:{}", host, port).parse::<SocketAddr>()?;
    let sec_lvl = get_security_lvl(matches)?;

    info!("Security level set to '{}'", sec_lvl);

    emerald::rpc::start(&addr, storage_ctrl, Some(sec_lvl));

    Ok(())
}

/// Show user balance
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
///
fn balance_cmd(matches: &ArgMatches) -> ExecResult {
    match get_upstream(matches) {
        Ok(ref rpc) => {
            let addr = get_address(matches, "address").expect("Required account address");
            let balance = rpc::request_balance(rpc, &addr)?;
            info!("Balance for {} account", &addr);
            println!("{}", balance);

            Ok(())
        }
        Err(e) => Err(Error::ExecError(format!(
            "Can't get balance: {}",
            e.to_string()
        ))),
    }
}

/// Creates new BIP39 mnemonic phrase
/// Refer [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
/// for more info
///
fn mnemonic_cmd() -> ExecResult {
    let entropy = gen_entropy(ENTROPY_BYTE_LENGTH)?;
    let mn = Mnemonic::new(Language::English, &entropy)?;
    println!("{}", mn.sentence());
    Ok(())
}

/// Request `nonce` for specified account from a remote node
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
///
fn nonce_cmd(matches: &ArgMatches) -> ExecResult {
    let addr = get_address(matches, "address").expect("Required account address");
    let nonce = get_nonce(&matches, &addr)?;

    info!("Nonce for {} account", &addr);
    if matches.is_present("hex") {
        println!("{:x}", nonce);
    } else {
        println!("{}", nonce);
    }

    Ok(())
}
