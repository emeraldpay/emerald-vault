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
use super::emerald::mnemonic::{Language, Mnemonic, StandardMnemonic};
use super::emerald::storage::{default_path, KeyfileStorage, StorageController};
use super::emerald::PrivateKey;
use super::emerald::{self, align_bytes, to_arr, to_even_str, trim_hex, Address, Transaction};
use clap::ArgMatches;
use std::path::PathBuf;

type ExecResult = Result<(), Error>;

const DEFAULT_CHAIN_NAME: &str = "mainnet";

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
        ("account", Some(sub_m)) => account_cmd(sub_m, storage_ctrl.get_keystore(chain)?, &env),
        ("transaction", Some(sub_m)) => {
            transaction_cmd(sub_m, storage_ctrl.get_keystore(chain)?, &env, chain)
        }
        ("mnemonic", Some(_)) => mnemonic_cmd(),
        _ => Err(Error::ExecError(
            "No command selected. Use `-h` for help".to_string(),
        )),
    }
}

/// Creates new BIP39 mnemonic phrase
/// Refer [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
/// for more info
///
fn mnemonic_cmd() -> ExecResult {
    let mn = Mnemonic::new(Language::English, StandardMnemonic::size15())?;
    println!("{}", mn.sentence());
    Ok(())
}
