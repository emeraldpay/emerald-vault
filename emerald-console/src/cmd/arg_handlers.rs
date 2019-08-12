//! # Helpers for command execution

use super::Error;
use super::{
    align_bytes, to_arr, to_even_str, trim_hex, Address, ArgMatches, KdfDepthLevel, PrivateKey,
    DEFAULT_UPSTREAM,
};
use hex::FromHex;
use reqwest::Url;
use rpassword;
use rpc::{self, RpcConnector};
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;

/// Environment variables used to change default variables
#[derive(Default, Debug)]
pub struct EnvVars {
    pub emerald_base_path: Option<String>,
    pub emerald_host: Option<String>,
    pub emerald_port: Option<String>,
    pub emerald_chain: Option<String>,
    pub emerald_chain_id: Option<String>,
    pub emerald_gas: Option<String>,
    pub emerald_gas_price: Option<String>,
    pub emerald_security_level: Option<String>,
    pub emerald_node: Option<String>,
}

impl EnvVars {
    /// Collect environment variables to overwrite default values
    pub fn parse() -> EnvVars {
        let mut vars = EnvVars::default();
        for (key, value) in env::vars() {
            match key.as_ref() {
                "EMERALD_BASE_PATH" => vars.emerald_base_path = Some(value),
                "EMERALD_HOST" => vars.emerald_host = Some(value),
                "EMERALD_PORT" => vars.emerald_port = Some(value),
                "EMERALD_CHAIN" => vars.emerald_chain = Some(value),
                "EMERALD_CHAIN_ID" => vars.emerald_chain_id = Some(value),
                "EMERALD_GAS" => vars.emerald_gas = Some(value),
                "EMERALD_GAS_PRICE" => vars.emerald_gas_price = Some(value),
                "EMERALD_SECURITY_LEVEL" => vars.emerald_security_level = Some(value),
                "EMERALD_NODE" => vars.emerald_node = Some(value),
                _ => (),
            }
        }
        vars
    }
}

/// Parse raw hex string arguments from user
fn parse_arg(raw: &str) -> Result<String, Error> {
    let s = raw
        .parse::<String>()
        .and_then(|s| Ok(to_even_str(trim_hex(&s))))?;

    if s.is_empty() {
        Err(Error::ExecError(
            "Invalid parameter: empty string".to_string(),
        ))
    } else {
        Ok(s)
    }
}

/// Converts hex string to 32 bytes array
/// Aligns original `hex` to fit 32 bytes
pub fn hex_to_32bytes(hex: &str) -> Result<[u8; 32], Error> {
    if hex.is_empty() {
        return Err(Error::ExecError(
            "Invalid parameter: empty string".to_string(),
        ));
    }

    let bytes = Vec::from_hex(hex)?;
    Ok(to_arr(&align_bytes(&bytes, 32)))
}

/// Parse address from command-line argument
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * env - environment variables
///
pub fn get_gas_price(matches: &ArgMatches, env: &EnvVars) -> Result<[u8; 32], Error> {
    let gas_pr = match matches
        .value_of("gas-price")
        .or_else(|| env.emerald_gas_price.as_ref().map(String::as_str))
    {
        Some(g) => g.to_string(),
        None => get_upstream(matches).and_then(|rpc| rpc::request_gas_price(&rpc))?,
    };
    hex_to_32bytes(trim_hex(&gas_pr))
}

/// Parse address from command-line argument
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * env - environment variables
///
pub fn get_gas_limit(matches: &ArgMatches, env: &EnvVars) -> Result<u64, Error> {
    let gas = match matches
        .value_of("gas")
        .or_else(|| env.emerald_gas.as_ref().map(String::as_str))
    {
        Some(g) => g.to_string(),
        None => get_upstream(matches).and_then(|rpc| rpc::request_gas(&rpc))?,
    };
    u64::from_str_radix(trim_hex(&gas), 16).map_err(Error::from)
}

/// Get nonce value for provided address
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * addr - account address
///
pub fn get_nonce(matches: &ArgMatches, addr: &Address) -> Result<u64, Error> {
    let nonce = match matches.value_of("nonce") {
        Some(n) => n.to_string(),
        None => get_upstream(matches).and_then(|rpc| rpc::request_nonce(&rpc, addr))?,
    };
    u64::from_str_radix(trim_hex(&nonce), 16).map_err(Error::from)
}

/// Parse address from command-line argument
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * arg_name - argument name
///
pub fn get_address(matches: &ArgMatches, arg_name: &str) -> Result<Address, Error> {
    let s = &matches
        .value_of(arg_name)
        .expect("Required account address");

    Address::from_str(s).map_err(Error::from)
}

/// Parse address from command-line argument
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
///
pub fn get_upstream(matches: &ArgMatches) -> Result<RpcConnector, Error> {
    let ups = matches.value_of("upstream").unwrap_or(DEFAULT_UPSTREAM);
    parse_socket(ups)
        .or_else(|_| parse_url(ups))
        .and_then(|url| Ok(RpcConnector { url }))
}

/// Parse address from command-line argument
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
///
pub fn get_security_lvl(matches: &ArgMatches) -> Result<KdfDepthLevel, Error> {
    let kdf = match matches.value_of("security-level") {
        Some(sec) => KdfDepthLevel::from_str(sec)?,
        None => KdfDepthLevel::default(),
    };

    Ok(kdf)
}

/// Parse private key for account creation
pub fn parse_pk(s: &str) -> Result<PrivateKey, Error> {
    let pk_str = s.parse::<String>()?;
    let pk = PrivateKey::from_str(&pk_str)?;
    Ok(pk)
}

/// Parse transaction value
pub fn parse_value(s: &str) -> Result<[u8; 32], Error> {
    let value_str = parse_arg(s)?;
    hex_to_32bytes(&value_str)
}

/// Parse transaction data
pub fn parse_data(s: &str) -> Result<Vec<u8>, Error> {
    match s.len() {
        0 => Ok(vec![]),
        _ => {
            let data = parse_arg(s)?;
            Vec::from_hex(data).map_err(Error::from)
        }
    }
}

/// Parse URL for ethereum node
pub fn parse_url(s: &str) -> Result<Url, Error> {
    let addr: Url = s.parse()?;
    Ok(addr)
}

/// Parse socket address for ethereum node
pub fn parse_socket(s: &str) -> Result<Url, Error> {
    let addr = s
        .parse::<SocketAddr>()
        .map_err(Error::from)
        .and_then(|a| format!("https://{}", a).parse().map_err(Error::from))?;

    Ok(addr)
}

/// Request passphrase
pub fn request_passphrase() -> Result<String, Error> {
    println!("Enter passphrase: ");
    let passphrase = rpassword::read_password().unwrap();

    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_convert_hex_to_32bytes() {
        assert_eq!(
            hex_to_32bytes("fa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f",)
                .unwrap(),
            [
                0xfa, 0x38, 0x4e, 0x6f, 0xe9, 0x15, 0x74, 0x7c, 0xd1, 0x3f, 0xaa, 0x10, 0x22, 0x04,
                0x4b, 0x0d, 0xef, 0x5e, 0x6b, 0xec, 0x42, 0x38, 0xbe, 0xc5, 0x31, 0x66, 0x48, 0x7a,
                0x5c, 0xca, 0x56, 0x9f,
            ]
        );
        assert_eq!(hex_to_32bytes("00").unwrap(), [0u8; 32]);
        assert_eq!(hex_to_32bytes("0000").unwrap(), [0u8; 32]);
        assert!(hex_to_32bytes("00_10000").is_err());
        assert!(hex_to_32bytes("01000z").is_err());
        assert!(hex_to_32bytes("").is_err());
    }

    #[test]
    fn should_parse_arg() {
        assert_eq!(parse_arg("0x1000").unwrap(), "1000");
        assert_eq!(parse_arg("0x100").unwrap(), "0100");
        assert_eq!(parse_arg("0x10000").unwrap(), "010000");
        assert!(parse_arg("0x").is_err());
        assert!(parse_arg("").is_err());
    }

    #[test]
    fn should_parse_private_key() {
        let pk = PrivateKey::try_from(&[0u8; 32]).unwrap();
        assert_eq!(
            pk,
            parse_pk("0x0000000000000000000000000000000000000000000000000000000000000000",)
                .unwrap()
        );
    }

    #[test]
    fn should_parse_value() {
        assert_eq!(parse_value("0x00").unwrap(), [0u8; 32]);
        assert_eq!(parse_value("000").unwrap(), [0u8; 32]);
        assert!(parse_value("00_10000").is_err());
        assert!(parse_value("01000z").is_err());
        assert!(parse_value("").is_err());
    }

    #[test]
    fn should_parse_data() {
        assert_eq!(parse_data("0x00").unwrap(), vec![0]);
        assert_eq!(parse_data("000").unwrap(), vec![0, 0]);
        assert_eq!(parse_data("").unwrap(), Vec::new() as Vec<u8>);
        assert!(parse_data("00_10000").is_err());
        assert!(parse_data("01000z").is_err());
    }

    #[test]
    fn should_parse_socket_addr() {
        assert_eq!(
            parse_socket("127.0.0.1:8545").unwrap(),
            Url::parse("https://127.0.0.1:8545").unwrap()
        );

        assert!(parse_socket(";akjf.com").is_err());
        assert!(parse_socket("https://127.0.0.1:8545").is_err());
    }

    #[test]
    fn should_parse_url_name() {
        assert_eq!(
            parse_url("https://www.gastracker.io").unwrap(),
            Url::parse("https://www.gastracker.io").unwrap()
        );

        assert!(parse_url("127.0.0.1:8545").is_err());
        assert!(parse_url("12344.com").is_err());
    }
}
