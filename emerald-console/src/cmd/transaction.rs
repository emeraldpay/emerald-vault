//! # Transaction related subcommands

use super::arg_handlers::*;
use super::{ArgMatches, EnvVars, Error, ExecResult, KeyfileStorage, PrivateKey, Transaction};
use crate::emerald::{to_chain_id, Address};
use hex::{ToHex};
use std::str::FromStr;

/// Hide account from being listed
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
/// * sec_level - key derivation depth
/// * chain - chain name
///
pub fn transaction_cmd(
    matches: &ArgMatches,
    storage: &Box<dyn KeyfileStorage>,
    env: &EnvVars,
    chain: &str,
) -> ExecResult {
    match matches.subcommand() {
        ("new", Some(sub_m)) => new(sub_m, env, storage, chain),
        _ => Err(Error::ExecError(
            "Invalid transaction subcommand. Use `emerald transaction -h` for help".to_string(),
        )),
    }
}

/// Create new transaction
///
///  # Arguments:
///
///  * matches -
///  * env -
///  * storage -
///  * chain - chain name
///
fn new(
    matches: &ArgMatches,
    env: &EnvVars,
    storage: &Box<dyn KeyfileStorage>,
    chain: &str,
) -> ExecResult {
    let (_, kf) = get_address(matches, "address")
        .and_then(|from| storage.search_by_address(&from).map_err(Error::from))?;
    let pk = request_passphrase().and_then(|pass| kf.decrypt_key(&pass).map_err(Error::from))?;
    let signed = build_tx(matches, env).and_then(|tr| sign_tx(&tr, pk, chain))?;

    println!("{}", signed.to_hex());

    Ok(())
}

/// Build transaction for provided arguments
/// If argument missing, try to use envirment vars
/// or request value through RPC
///
///  # Arguments:
///
///  * matches -
///  * env -
///
fn build_tx(matches: &ArgMatches, env: &EnvVars) -> Result<Transaction, Error> {
    let value = matches
        .value_of("value")
        .ok_or_else(|| Error::ExecError("Required value to send".to_string()))
        .and_then(|s| parse_value(s))?;

    let to = match matches.value_of("to") {
        Some(s) => Some(Address::from_str(s)?),
        None => None,
    };

    let data = match matches.value_of("data") {
        Some(s) => parse_data(s)?,
        None => vec![],
    };

    Ok(Transaction {
        nonce: get_nonce(matches)?,
        gas_price: get_gas_price(matches, env)?,
        gas_limit: get_gas_limit(matches, env)?,
        to,
        value,
        data,
    })
}

/// Sign transaction with private key
///
///  # Arguments:
///
///  * matches -
///  * env -
///
fn sign_tx(tr: &Transaction, pk: PrivateKey, chain: &str) -> Result<Vec<u8>, Error> {
    if let Some(chain_id) = to_chain_id(chain) {
        let raw = tr.to_signed_raw(pk, chain_id)?;
        Ok(raw)
    } else {
        Err(Error::ExecError("Invalid chain name".to_string()))
    }
}
