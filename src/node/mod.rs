//! # Node managment

mod error;
mod geth_control;

pub use self::error::Error;
pub use self::geth_control::GethController;
use super::util::timestamp;
use std::str::FromStr;
/// Chain type
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Chain {
    /// Main net
    Mainnet,

    /// Test net, aka. Morden
    Testnet,
}

/// Control over local client
pub trait NodeController {
    /// Starts client with specified chain
    fn start(&mut self, c: Chain) -> Result<(), Error>;

    /// Stops client
    fn stop(&mut self) -> Result<(), Error>;

    /// Switch client to a new chain
    /// Note: it will destroy previous client's process
    ///
    /// # Arguments:
    /// c - chain type
    ///
    fn switch(&mut self, c: Chain) -> Result<(), Error>;
}

/// Try to parse string into chain type
pub fn parse_chain(s: &str) -> Result<Chain, Error> {
    Chain::from_str(s)
}

/// File name for log file.
/// client-<yyy-mm-ddThh-mm-ss>.log
pub fn get_log_name() -> String {
    let mut name = String::from("client-");
    name.push_str(&timestamp());
    name.push_str(".log");
    name
}

impl FromStr for Chain {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "MAINNET" => Ok(Chain::Mainnet),
            "TESTNET" => Ok(Chain::Testnet),
            v => Err(Error::InvalidChain(v.to_string())),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tests::*;

    #[test]
    fn should_parse_chain_type() {}

    #[test]
    fn should_fail_on_invalid_chain() {}

    #[test]
    fn should_generate_log_name() {}
}
