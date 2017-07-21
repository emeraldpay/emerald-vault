use super::Error;
use super::serialize::RPCTransaction;

use core::{Address, Transaction};
use hdwallet::{WManager, to_prefixed_path};
use jsonrpc_core::{Params, Value};
use keystore::{self, CryptoType, KdfDepthLevel, KeyFile};
use rustc_serialize::json as rustc_json;
use serde_json;
use std::cell::RefCell;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;
use util;

fn to_chain_id(chain: &str, chain_id: Option<usize>, default_id: u8) -> u8 {
    if chain_id.is_some() {
        return chain_id.unwrap() as u8;
    }

    util::to_chain_id(chain).unwrap_or(default_id)
}

fn check_chain_params(chain: &str, chain_id: usize) -> Result<(), Error> {
    if let Some(id) = util::to_chain_id(chain) {
        if id as usize != chain_id {
            return Err(Error::InvalidDataFormat(
                "Inconsistent chain parameters".to_string(),
            ));
        }
    };

    Ok(())
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Either<T, U> {
    Left(T),
    Right(U),
}

impl<T, U: Default> Either<T, U> {
    pub fn into_right(self) -> U {
        match self {
            Either::Left(_) => U::default(),
            Either::Right(u) => u,
        }
    }
}

impl<T, U: Default> Either<(T,), (T, U)> {
    fn into_full(self) -> (T, U) {
        match self {
            Either::Left((t,)) => (t, U::default()),
            Either::Right((t, u)) => (t, u),
        }
    }
}

pub fn current_version(_params: ()) -> Result<&'static str, Error> {
    Ok(::version())
}

pub fn heartbeat(_params: ()) -> Result<i64, Error> {
    use time::get_time;
    let res = get_time().sec;
    debug!("Emerald heartbeat: {}", res);

    Ok(res)
}

#[derive(Serialize, Debug)]
pub struct ListAccountAccount {
    name: String,
    address: String,
    hardware: bool,
}

#[derive(Deserialize, Default, Debug)]
pub struct ListAccountsAdditional {
    #[serde(default)]
    chain: String,
    #[serde(default)]
    chain_id: Option<usize>,
    #[serde(default)]
    show_hidden: bool,
    #[serde(default)]
    hd_path: Option<String>,
}

pub fn list_accounts(
    params: Either<(), (ListAccountsAdditional,)>,
    keystore_path: &PathBuf,
) -> Result<Vec<ListAccountAccount>, Error> {
    let (additional,) = params.into_right();
    let res = keystore::list_accounts(keystore_path, additional.show_hidden)?
        .iter()
        .map(|&(ref name, ref address, is_hd)| {
            ListAccountAccount {
                name: name.clone(),
                address: address.clone(),
                hardware: is_hd,
            }
        })
        .collect();
    debug!(
        "Accounts listed with `show_hidden`: {}\n\t{:?}",
        additional.show_hidden,
        res
    );

    Ok(res)
}

#[derive(Deserialize, Default, Debug)]
pub struct CommonAdditional {
    #[serde(default)]
    chain: String,
    #[serde(default)]
    chain_id: Option<usize>,
}

#[derive(Deserialize)]
pub struct HideAccountAccount {
    address: String,
}

pub fn hide_account(
    params: Either<(HideAccountAccount,), (HideAccountAccount, CommonAdditional)>,
    keystore_path: &PathBuf,
) -> Result<bool, Error> {
    let (account, _) = params.into_full();
    let addr = Address::from_str(&account.address)?;
    let res = keystore::hide(&addr, keystore_path)?;
    debug!("Account hided: {}", addr);

    Ok(res)
}

#[derive(Deserialize)]
pub struct UnhideAccountAccount {
    address: String,
}

pub fn unhide_account(
    params: Either<(UnhideAccountAccount,), (UnhideAccountAccount, CommonAdditional)>,
    keystore_path: &PathBuf,
) -> Result<bool, Error> {
    let (account, _) = params.into_full();
    let addr = Address::from_str(&account.address)?;
    let res = keystore::unhide(&addr, keystore_path)?;
    debug!("Account unhided: {}", addr);

    Ok(res)
}

#[derive(Deserialize)]
pub struct ShakeAccountAccount {
    address: String,
    old_passphrase: String,
    new_passphrase: String,
}

pub fn shake_account(
    params: Either<(ShakeAccountAccount,), (ShakeAccountAccount, CommonAdditional)>,
    keystore_path: &PathBuf,
) -> Result<bool, Error> {
    use keystore::os_random;

    let (account, _) = params.into_full();
    let addr = Address::from_str(&account.address)?;

    let (_, kf) = KeyFile::search_by_address(&addr, keystore_path)?;

    match kf.crypto {
        CryptoType::Core(ref core) => {
            let pk = kf.decrypt_key(&account.old_passphrase)?;
            let new_kf = KeyFile::new_custom(
                pk,
                &account.new_passphrase,
                core.kdf,
                &mut os_random(),
                kf.name,
                kf.description,
            )?;
            new_kf.flush(keystore_path)?;
            debug!("Account shaked: {}", kf.address);
        }
        _ => {
            return Err(Error::InvalidDataFormat(
                "Can't shake account from HD wallet".to_string(),
            ))
        }
    };

    Ok(true)
}

#[derive(Deserialize)]
pub struct UpdateAccountAccount {
    #[serde(default)]
    address: String,
    #[serde(default)]
    name: String,
    description: String,
}

pub fn update_account(
    params: Either<(UpdateAccountAccount,), (UpdateAccountAccount, CommonAdditional)>,
    keystore_path: &PathBuf,
) -> Result<bool, Error> {
    let (account, _) = params.into_full();
    let addr = Address::from_str(&account.address)?;

    let (_, mut kf) = KeyFile::search_by_address(&addr, keystore_path)?;
    if !account.name.is_empty() {
        kf.name = Some(account.name);
    }
    if !account.description.is_empty() {
        kf.description = Some(account.description);
    }
    kf.flush(keystore_path)?;
    debug!(
        "Account {} updated with name: {}, description: {}",
        kf.address,
        kf.name.unwrap_or_else(|| "".to_string()),
        kf.description.unwrap_or_else(|| "".to_string())
    );

    Ok(true)
}

pub fn import_account(
    params: Either<(Value,), (Value, CommonAdditional)>,
    keystore_path: &PathBuf,
) -> Result<String, Error> {
    let (raw, _) = params.into_full();
    let raw = serde_json::to_string(&raw)?;

    let kf = KeyFile::decode(raw.to_lowercase())?;
    kf.flush(keystore_path)?;

    debug!("Account imported: {}", kf.address);

    Ok(format!("{}", kf.address))
}

#[derive(Deserialize)]
pub struct ExportAccountAccount {
    address: String,
}

pub fn export_account(
    params: Either<(ExportAccountAccount,), (ExportAccountAccount, CommonAdditional)>,
    keystore_path: &PathBuf,
) -> Result<Value, Error> {
    let (account, _) = params.into_full();
    let addr = Address::from_str(&account.address)?;

    let (_, kf) = KeyFile::search_by_address(&addr, keystore_path)?;
    let raw = rustc_json::encode(&kf)?;
    let value = serde_json::to_value(&raw)?;
    debug!("Account exported: {}", kf.address);

    Ok(value)
}

#[derive(Deserialize, Debug)]
pub struct NewAccountAccount {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    passphrase: String,
}

pub fn new_account(
    params: Either<(NewAccountAccount,), (NewAccountAccount, CommonAdditional)>,
    sec: &KdfDepthLevel,
    keystore_path: &PathBuf,
) -> Result<String, Error> {
    let (account, _) = params.into_full();
    if account.passphrase.is_empty() {
        return Err(Error::InvalidDataFormat("Empty passphase".to_string()));
    }

    let kf = KeyFile::new(
        &account.passphrase,
        sec,
        Some(account.name),
        Some(account.description),
    )?;

    let addr = kf.address.to_string();
    kf.flush(keystore_path)?;
    debug!("New account generated: {}", kf.address);

    Ok(addr)
}

#[derive(Deserialize)]
pub struct SignTransactionTransaction {
    pub from: String,
    pub to: String,
    pub gas: String,
    #[serde(rename = "gasPrice")]
    pub gas_price: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub data: String,
    pub nonce: String,
    pub passphrase: String,
}

#[derive(Deserialize, Default, Debug)]
pub struct SignTransactionAdditional {
    #[serde(default)]
    chain: String,
    #[serde(default)]
    chain_id: Option<usize>,
    #[serde(default)]
    hd_path: Option<String>,
}

pub fn sign_transaction(
    params: Either<
        (SignTransactionTransaction,),
        (SignTransactionTransaction, SignTransactionAdditional),
    >,
    keystore_path: &PathBuf,
    default_chain_id: u8,
    wallet_manager: &Mutex<RefCell<WManager>>,
) -> Result<Params, Error> {
    let (transaction, additional) = params.into_full();
    let addr = Address::from_str(&transaction.from)?;

    if additional.chain_id.is_some() {
        check_chain_params(&additional.chain, additional.chain_id.unwrap())?;
    }

    match KeyFile::search_by_address(&addr, keystore_path) {
        Ok((_, kf)) => {
            let rpc_transaction = RPCTransaction {
                from: transaction.from,
                to: transaction.to,
                gas: transaction.gas,
                gas_price: transaction.gas_price,
                value: transaction.value,
                data: transaction.data,
                nonce: transaction.nonce,
            };
            let chain_id = to_chain_id(&additional.chain, additional.chain_id, default_chain_id);
            match rpc_transaction.try_into() {
                Ok(tr) => {
                    match kf.crypto {
                        CryptoType::Core(_) => {
                            if let Ok(pk) = kf.decrypt_key(&transaction.passphrase) {
                                let raw = tr.to_signed_raw(pk, chain_id).expect(
                                    "Expect to sign a \
                                     transaction",
                                );
                                let signed = Transaction::to_raw_params(raw);
                                debug!(
                                    "Signed by emerald transaction to: {:?}\n\t raw: {:?}",
                                    &tr.to,
                                    signed
                                );

                                Ok(signed)
                            } else {
                                Err(Error::InvalidDataFormat("Invalid passphrase".to_string()))
                            }
                        }

                        CryptoType::HdWallet(hw) => {
                            let quard = wallet_manager.lock().unwrap();
                            let mut wm = quard.borrow_mut();

                            let hd_path = match to_prefixed_path(&hw.hd_path) {
                                Ok(hd) => hd,
                                Err(e) => {
                                    return Err(Error::InvalidDataFormat(
                                        format!("Invalid hd path format: {}", e.to_string()),
                                    ))
                                }
                            };

                            if let Err(e) = wm.update(Some(hd_path.clone())) {
                                return Err(Error::InvalidDataFormat(
                                    format!("Can't update HD wallets list : {}", e.to_string()),
                                ));
                            }

                            let mut err = String::new();
                            let rlp = tr.to_rlp();
                            for (addr, fd) in wm.devices() {
                                debug!("Selected device: {:?} {:?}", &addr, &fd);
                                match wm.sign_transaction(&fd, &rlp, Some(hd_path.clone())) {
                                    Ok(s) => {
                                        let raw = tr.raw_from_sig(chain_id, s);
                                        let signed = Transaction::to_raw_params(raw);
                                        debug!(
                                            "HD wallet addr:{:?} path: {:?} signed transaction to: \
                                             {:?}\n\t raw: {:?}",
                                            addr,
                                            fd,
                                            &tr.to,
                                            signed
                                        );
                                        return Ok(signed);
                                    }
                                    Err(e) => {
                                        err = format!(
                                            "{}\nWallet addr:{} on path:{}, can't sign \
                                             transaction: {}",
                                            err,
                                            addr,
                                            fd,
                                            e.to_string()
                                        );
                                        continue;
                                    }
                                }
                            }

                            Err(Error::InvalidDataFormat(err))
                        }
                    }
                }
                Err(err) => Err(Error::InvalidDataFormat(err.to_string())),
            }
        }

        Err(_) => Err(Error::InvalidDataFormat("Can't find account".to_string())),
    }
}
