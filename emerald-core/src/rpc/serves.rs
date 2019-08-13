/*
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
*/
use super::common::{
    extract_chain_params, CommonAdditional, Either, FunctionParams, ListAccountAccount,
    ListAccountsAdditional, NewAccountAccount, NewMnemonicAccount, SelectedAccount,
    ShakeAccountAccount, SignData, SignTxAdditional, SignTxTransaction, UpdateAccountAccount,
};
use super::Error;
use super::StorageController;
use crate::contract::Contract;
use crate::core::{Address, Transaction};
use crate::hdwallet::bip32::to_prefixed_path;
use crate::hdwallet::WManager;
use jsonrpc_core::{Params, Value};
use crate::keystore::{os_random, CryptoType, Kdf, KdfDepthLevel, KeyFile, PBKDF2_KDF_NAME};
use crate::mnemonic::{self, gen_entropy, HDPath, Language, Mnemonic, ENTROPY_BYTE_LENGTH};
use serde_json;
use std::cell::RefCell;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use crate::util;
use hex;

pub fn current_version() -> Result<&'static str, Error> {
    Ok(crate::version())
}

pub fn heartbeat() -> Result<i64, Error> {
    use time::get_time;
    let res = get_time().sec;
    debug!("Emerald heartbeat: {}", res);

    Ok(res)
}

pub fn list_accounts(
    params: Either<(), (ListAccountsAdditional,)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Vec<ListAccountAccount>, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (additional,) = params.into_right();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    let res = storage
        .list_accounts(additional.show_hidden)?
        .iter()
        .map(|info| ListAccountAccount {
            name: info.name.clone(),
            address: info.address.clone(),
            description: info.description.clone(),
            hardware: info.is_hardware,
            is_hidden: info.is_hidden,
        })
        .collect();
    debug!(
        "Accounts listed with `show_hidden`: {}\n\t{:?}",
        additional.show_hidden, res
    );

    Ok(res)
}

pub fn hide_account(
    params: Either<(SelectedAccount,), (SelectedAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<bool, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    let addr = Address::from_str(&account.address)?;
    let res = storage.hide(&addr)?;
    debug!("Account hided: {}", addr);

    Ok(res)
}

pub fn unhide_account(
    params: Either<(SelectedAccount,), (SelectedAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<bool, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    let addr = Address::from_str(&account.address)?;
    let res = storage.unhide(&addr)?;
    debug!("Account unhided: {}", addr);

    Ok(res)
}

pub fn shake_account(
    params: Either<(ShakeAccountAccount,), (ShakeAccountAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<bool, Error> {

    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    let addr = Address::from_str(&account.address)?;

    let (_, kf) = storage.search_by_address(&addr)?;
    match kf.crypto {
        CryptoType::Core(ref core) => {
            let pk = kf.decrypt_key(&account.old_passphrase)?;
            let new_kf = KeyFile::new_custom(
                pk,
                &account.new_passphrase,
                core.kdf_params.kdf,
                &mut os_random(),
                kf.name,
                kf.description,
            )?;
            storage.put(&new_kf)?;
            debug!("Account shaked: {}", kf.address);
        }
        _ => {
            return Err(Error::InvalidDataFormat(
                "Can't shake account from HD wallet".to_string(),
            ));
        }
    };

    Ok(true)
}

pub fn update_account(
    params: Either<(UpdateAccountAccount,), (UpdateAccountAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<bool, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    let addr = Address::from_str(&account.address)?;

    let (_, mut kf) = storage.search_by_address(&addr)?;
    if !account.name.is_empty() {
        kf.name = Some(account.name);
    }
    if !account.description.is_empty() {
        kf.description = Some(account.description);
    }

    storage.put(&kf)?;
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
    storage: &Arc<Mutex<StorageController>>,
) -> Result<String, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (raw, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    let raw = serde_json::to_string(&raw)?;

    let kf = KeyFile::decode(&raw)?;
    storage.put(&kf)?;

    debug!("Account imported: {}", kf.address);

    Ok(format!("{}", kf.address))
}

pub fn export_account(
    params: Either<(SelectedAccount,), (SelectedAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Value, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    let addr = Address::from_str(&account.address)?;

    let (_, kf) = storage.search_by_address(&addr)?;
    let value = serde_json::to_value(&kf)?;
    debug!("Account exported: {}", kf.address);

    Ok(value)
}

pub fn new_account(
    params: Either<(NewAccountAccount,), (NewAccountAccount, CommonAdditional)>,
    sec: &KdfDepthLevel,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<String, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
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
    storage.put(&kf)?;
    debug!("New account generated: {}", kf.address);

    Ok(addr)
}

pub fn sign_transaction(
    params: Either<(SignTxTransaction,), (SignTxTransaction, SignTxAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
    wallet_manager: &Arc<Mutex<RefCell<WManager>>>,
) -> Result<Params, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (transaction, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    let addr = Address::from_str(&transaction.from)?;
    let (_chain, chain_id) = extract_chain_params(&additional)?;
    let passphrase = transaction.passphrase.clone();

    match storage.search_by_address(&addr) {
        Ok((_, kf)) => {
            match transaction.try_into() {
                Ok(tr) => {
                    match kf.crypto {
                        CryptoType::Core(_) => {
                            if passphrase.is_none() {
                                return Err(Error::InvalidDataFormat(
                                    "Missing passphrase".to_string(),
                                ));
                            }
                            let pass = passphrase.unwrap();

                            if let Ok(pk) = kf.decrypt_key(&pass) {
                                let raw = tr
                                    .to_signed_raw(pk, chain_id)
                                    .expect("Expect to sign a transaction");
                                let signed = Transaction::to_raw_params(&raw);
                                debug!("Signed transaction to: {:?}\n\t raw: {:?}", &tr.to, signed);

                                Ok(signed)
                            } else {
                                Err(Error::InvalidDataFormat("Invalid passphrase".to_string()))
                            }
                        }

                        CryptoType::HdWallet(hw) => {
                            let guard = wallet_manager.lock().unwrap();
                            let mut wm = guard.borrow_mut();

                            let hd_path = match to_prefixed_path(&hw.hd_path) {
                                Ok(hd) => hd,
                                Err(e) => return Err(Error::InvalidDataFormat(e.to_string())),
                            };
                            debug!("Sign with HD Wallet. HDPath {} (={}), chain_id {}",
                                   &hw.hd_path, hex::encode(&hd_path), &chain_id);

                            if let Err(e) = wm.update(Some(hd_path.clone())) {
                                return Err(Error::InvalidDataFormat(format!(
                                    "Can't update HD wallets list : {}",
                                    e.to_string()
                                )));
                            }

                            let mut err = String::new();
                            let rlp = tr.to_rlp(Some(chain_id));
                            for (addr, fd) in wm.devices() {
                                debug!("Selected device: {:?} {:?}", &addr, &fd);

                                // MUST verify address before making a signature, or a malicious
                                // person can replace HD path with another one and convince user to
                                // make signature from this address
                                match wm.get_address(&fd, Some(hd_path.clone())) {
                                    Ok(actual_addr) => {
                                        if actual_addr != addr {
                                            return Err(Error::InvalidDataFormat(
                                                "Address for stored HD path is incorrect"
                                                    .to_string(),
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        return Err(Error::InvalidDataFormat(format!(
                                            "Can't get Address for HD Path: {}",
                                            e.to_string()
                                        )));
                                    }
                                }

                                match wm.sign_transaction(&fd, &rlp, Some(hd_path.clone())) {
                                    Ok(s) => {
                                        // chain is None because don't need it for Ledger
                                        let raw = tr.raw_from_sig(None, &s);
                                        let signed = Transaction::to_raw_params(&raw);
                                        debug!(
                                            "HD wallet addr:{:?} path: {:?} signed transaction \
                                             to: {:?}\n\t raw: {:?}",
                                            addr, fd, &tr.to, signed
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

pub fn sign(
    params: Either<(SignData,), (SignData, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
    wallet_manager: &Arc<Mutex<RefCell<WManager>>>,
) -> Result<Params, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (input, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    let addr = Address::from_str(&input.address)?;
    let hash = util::keccak256(
        format!(
            "\x19Ethereum Signed Message:\n{}{}",
            input.data.len(),
            input.data
        )
            .as_bytes(),
    );
    match storage.search_by_address(&addr) {
        Ok((_, kf)) => {
            match kf.crypto {
                CryptoType::Core(_) => {
                    if input.passphrase.is_none() {
                        return Err(Error::InvalidDataFormat("Missing passphrase".to_string()));
                    }
                    let pass = input.passphrase.unwrap();
                    if let Ok(pk) = kf.decrypt_key(&pass) {
                        let signed = pk.sign_hash(hash)?;
                        Ok(Params::Array(vec![Value::String(signed.into())]))
                    } else {
                        Err(Error::InvalidDataFormat("Invalid passphrase".to_string()))
                    }
                }

                CryptoType::HdWallet(hw) => {
                    let guard = wallet_manager.lock().unwrap();
                    let mut wm = guard.borrow_mut();

                    let hd_path = match to_prefixed_path(&hw.hd_path) {
                        Ok(hd) => hd,
                        Err(e) => return Err(Error::InvalidDataFormat(e.to_string())),
                    };

                    if let Err(e) = wm.update(Some(hd_path.clone())) {
                        return Err(Error::InvalidDataFormat(format!(
                            "Can't update HD wallets list : {}",
                            e.to_string()
                        )));
                    }

                    let mut err = String::new();
                    for (addr, fd) in wm.devices() {
                        debug!("Selected device: {:?} {:?}", &addr, &fd);

                        // MUST verify address before making a signature, or a malicious
                        // person can replace HD path with another one and convince user to
                        // make signature from this address
                        match wm.get_address(&fd, Some(hd_path.clone())) {
                            Ok(actual_addr) => {
                                if actual_addr != addr {
                                    return Err(Error::InvalidDataFormat(
                                        "Address for stored HD path is incorrect".to_string(),
                                    ));
                                }
                            }
                            Err(e) => {
                                return Err(Error::InvalidDataFormat(format!(
                                    "Can't get Address for HD Path: {}",
                                    e.to_string()
                                )));
                            }
                        }

                        match wm.sign(&fd, &hash, &Some(hd_path.clone())) {
                            Ok(s) => {
                                debug!(
                                    "HD wallet addr:{:?} path: {:?} signed data to: {:?}\n\t raw: \
                                     {:?}",
                                    addr, fd, input.data, s
                                );
                                return Ok(Params::Array(vec![Value::String(s.into())]));
                            }
                            Err(e) => {
                                err = format!(
                                    "{}\nWallet addr:{} on path:{}, can't sign data: {}",
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
        Err(_) => Err(Error::InvalidDataFormat("Can't find account".to_string())),
    }
}

pub fn encode_function_call(
    params: Either<(Value,), (Value, FunctionParams)>,
) -> Result<String, Error> {
    let (_, inputs) = params.into_full();

    Contract::serialize_params(&inputs.types, inputs.values).map_err(From::from)
}

pub fn list_contracts(
    params: Either<(), (CommonAdditional,)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Vec<serde_json::Value>, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (additional,) = params.into_right();
    let storage = storage_ctrl.get_contracts(&additional.chain)?;

    Ok(storage.list())
}

pub fn import_contract(
    params: Either<(Value,), (Value, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<(), Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (raw, additional) = params.into_full();
    let storage = storage_ctrl.get_contracts(&additional.chain)?;

    storage.add(&raw)?;
    Ok(())
}

pub fn list_addresses(
    params: Either<(), (CommonAdditional,)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Vec<serde_json::Value>, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (additional,) = params.into_right();
    let storage = storage_ctrl.get_addressbook(&additional.chain)?;

    Ok(storage.list())
}

pub fn import_address(
    params: Either<(Value,), (Value, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<String, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (raw, additional) = params.into_full();
    let storage = storage_ctrl.get_addressbook(&additional.chain)?;

    storage.add(&raw)?;
    Ok(raw.get("address").unwrap().to_string())
}

pub fn delete_address(
    params: Either<(Value,), (Value, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<(), Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (addr, additional) = params.into_full();
    let storage = storage_ctrl.get_addressbook(&additional.chain)?;

    storage.delete(&addr)?;
    Ok(())
}

//pub fn export_contract(
//    params: Either<(Value,), (Value, FunctionParams)>,
//    storage: &Arc<Mutex<StorageController>>,
//) -> Result<Value, Error> {
//    let storage_ctrl = storage.lock().unwrap();
//    let (_, inputs) = params.into_full();
//    let storage = storage_ctrl.get_contracts(&additional.chain)?;
//}

pub fn generate_mnemonic() -> Result<String, Error> {
    let entropy = gen_entropy(ENTROPY_BYTE_LENGTH)?;
    let mnemonic = Mnemonic::new(Language::English, &entropy)?;

    Ok(mnemonic.sentence())
}

pub fn import_mnemonic(
    params: Either<(NewMnemonicAccount,), (NewMnemonicAccount, CommonAdditional)>,
    sec: &KdfDepthLevel,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<String, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let storage = storage_ctrl.get_keystore(&additional.chain)?;
    if account.password.is_empty() {
        return Err(Error::InvalidDataFormat("Empty password".to_string()));
    }

    let mnemonic = Mnemonic::try_from(Language::English, &account.mnemonic)?;
    let hd_path = HDPath::try_from(&account.hd_path)?;
    let pk = mnemonic::generate_key(&hd_path, &mnemonic.seed(""))?;

    let kdf = if cfg!(target_os = "windows") {
        Kdf::from_str(PBKDF2_KDF_NAME)?
    } else {
        Kdf::from(*sec)
    };

    let mut rng = os_random();
    let kf = KeyFile::new_custom(
        pk,
        &account.password,
        kdf,
        &mut rng,
        Some(account.name),
        Some(account.description),
    )?;

    let addr = kf.address.to_string();
    storage.put(&kf)?;
    debug!("New mnemonic account generated: {}", kf.address);

    Ok(addr)
}
