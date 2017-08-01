mod error;
mod contracts;
mod serialize;

pub use self::error::Error;
pub use self::contracts::Contracts;
use ethabi::Interface;


/// Contract specification
#[derive(Clone, Debug, Deserialize)]
pub struct Contract {
    abi: Interface,
}