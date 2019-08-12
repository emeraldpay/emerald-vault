//! # Account related subcommands

use super::arg_handlers::*;
use super::emerald::storage::KeystoreError;
use super::{EnvVars, Error, ExecResult, KeyfileStorage};
use indicator::ProgressIndicator;
use serde_json;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{Address, KeyFile};
use clap::ArgMatches;
use std::fs;
use std::str::FromStr;

/// Hide account from being listed
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
/// * env - environment variables
///
pub fn account_cmd(
    matches: &ArgMatches,
    storage: &Box<KeyfileStorage>,
    env: &EnvVars,
) -> ExecResult {
    match matches.subcommand() {
        ("list", Some(sub_m)) => list(sub_m, storage),
        ("new", Some(sub_m)) => new(sub_m, storage),
        ("hide", Some(sub_m)) => toggle_visibility(sub_m, storage, |a| storage.hide(a)),
        ("unhide", Some(sub_m)) => toggle_visibility(sub_m, storage, |a| storage.unhide(a)),
        ("strip", Some(sub_m)) => strip(sub_m, storage),
        ("import", Some(sub_m)) => import(sub_m, storage, env),
        ("export", Some(sub_m)) => export(sub_m, storage, env),
        ("update", Some(sub_m)) => update(sub_m, storage),
        _ => Err(Error::ExecError(
            "Invalid account subcommand. Use `emerald account -h` for help".to_string(),
        )),
    }
}

/// List all accounts
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
///
fn list(matches: &ArgMatches, storage: &Box<KeyfileStorage>) -> ExecResult {
    let accounts_info = storage.list_accounts(matches.is_present("show-hidden"))?;

    println!("{0: <45} {1: <45} ", "ADDRESS", "NAME");
    for info in accounts_info {
        println!("{0: <45} {1: <45} ", &info.address, &info.name);
    }

    Ok(())
}

/// Creates new account
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
///
fn new(matches: &ArgMatches, storage: &Box<KeyfileStorage>) -> ExecResult {
    println!("! Warning: passphrase can't be restored. Don't forget it !");
    let passphrase = request_passphrase()?;
    let name = matches.value_of("name").map(String::from);
    let desc = matches.value_of("description").map(String::from);
    let sec_level = get_security_lvl(matches)?;
    info!("Security level: {}", sec_level);

    let ind = ProgressIndicator::start(Some("Generating new account".to_string()));
    let kf = match matches.value_of("raw") {
        Some(raw) => {
            let pk = parse_pk(raw)?;
            let mut k = KeyFile::new(&passphrase, &sec_level, name, desc)?;
            k.encrypt_key(pk, &passphrase);
            k
        }
        None => KeyFile::new(&passphrase, &sec_level, name, desc)?,
    };
    storage.put(&kf)?;

    ind.stop();
    println!("Created new account: {}", &kf.address.to_string());

    Ok(())
}

/// Toggle of account(s) for `list` operation.
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
/// * op - toggle operation to hide/unhide account(s)
///
fn toggle_visibility<U, F: Fn(&Address) -> Result<U, KeystoreError>>(
    matches: &ArgMatches,
    storage: &Box<KeyfileStorage>,
    toggle_op: F,
) -> ExecResult {
    if matches.is_present("all") {
        let accounts_info = storage.list_accounts(true)?;
        for info in accounts_info {
            let addr = Address::from_str(&info.address)?;
            toggle_op(&addr)?;
        }
    } else {
        let addr = get_address(matches, "address")?;
        toggle_op(&addr)?;
    }

    Ok(())
}

/// Extract private key from a `Keyfile`
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
///
fn strip(matches: &ArgMatches, storage: &Box<KeyfileStorage>) -> ExecResult {
    let address = get_address(matches, "address")?;

    let (_, kf) = storage.search_by_address(&address)?;
    let passphrase = request_passphrase()?;
    let pk = kf.decrypt_key(&passphrase)?;

    println!("Private key: {}", &pk.to_string());

    Ok(())
}

/// Export accounts
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
/// * env - environment variables
///
fn export(matches: &ArgMatches, storage: &Box<KeyfileStorage>, env: &EnvVars) -> ExecResult {
    let path = get_path(matches, env)?;

    let ind = ProgressIndicator::start(Some("Exporting Keyfiles".to_string()));
    if matches.is_present("all") {
        if !path.is_dir() {
            return Err(Error::ExecError(
                "`export`: invalid args. Use `-h` for help.".to_string(),
            ));
        }

        let accounts_info = storage.list_accounts(true)?;
        for info in accounts_info {
            let addr = Address::from_str(&info.address)?;
            export_keyfile(&path, storage, &addr)?
        }
    } else {
        get_address(matches, "address").and_then(|addr| export_keyfile(&path, storage, &addr))?
    }
    ind.stop();

    Ok(())
}

/// Import account(s)
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
/// * env - environment variables
///
fn import(matches: &ArgMatches, storage: &Box<KeyfileStorage>, env: &EnvVars) -> ExecResult {
    let path = get_path(matches, env)?;
    let mut counter = 0;

    let ind = ProgressIndicator::start(Some("Importing Keyfiles".to_string()));
    if path.is_file() {
        import_keyfile(path, storage, matches.is_present("force"))?;
        counter += 1;
    } else {
        let entries = fs::read_dir(&path)?;
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                continue;
            }
            import_keyfile(path, storage, matches.is_present("force"))?;
            counter += 1;
        }
    }
    ind.stop();

    println!("Imported accounts: {}", counter);

    Ok(())
}

/// Update `name` and `description` for existing account
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - `Keyfile` storage
///
fn update(matches: &ArgMatches, storage: &Box<KeyfileStorage>) -> ExecResult {
    let address = get_address(matches, "address")?;
    let name = matches.value_of("name").map(String::from);
    let desc = matches.value_of("description").map(String::from);

    storage.update(&address, name, desc)?;

    Ok(())
}

/// Parse address from command-line argument
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * env - environment variables
///
fn get_path(matches: &ArgMatches, env: &EnvVars) -> Result<PathBuf, Error> {
    matches
        .value_of("path")
        .or_else(|| env.emerald_base_path.as_ref().map(String::as_str))
        .and_then(|p| Some(PathBuf::from(p)))
        .ok_or_else(|| Error::ExecError("Expected path".to_string()))
}

/// Import single `Keyfile` into storage
///
/// # Arguments:
///
/// * addr - target addr
/// * path - target file path
///
pub fn import_keyfile<P: AsRef<Path>>(
    path: P,
    storage: &Box<KeyfileStorage>,
    force_mode: bool,
) -> Result<(), Error> {
    let mut json = String::new();
    File::open(path).and_then(|mut f| f.read_to_string(&mut json))?;

    let kf = KeyFile::decode(&json)?;

    match storage.is_addr_exist(&kf.address) {
        Ok(_) => {
            if force_mode {
                storage.put(&kf)?;
            }
        }
        Err(_) => storage.put(&kf)?,
    }

    Ok(())
}

/// Export single `Keyfile` for selected address
/// to the `JSON` file
///
/// # Arguments:
///
/// * addr - target addr
/// * path - target file path
///
pub fn export_keyfile(
    path: &Path,
    storage: &Box<KeyfileStorage>,
    addr: &Address,
) -> Result<(), Error> {
    let (info, kf) = storage.search_by_address(addr)?;

    let mut p = PathBuf::from(path);
    p.push(&info.filename);

    let json = serde_json::to_string(&kf).and_then(|s| Ok(s.into_bytes()))?;
    let mut f = fs::File::create(p)?;
    f.write_all(&json)?;

    Ok(())
}
