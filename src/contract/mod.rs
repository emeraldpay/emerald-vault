mod error;
mod contracts;

pub use self::contracts::Contracts;
pub use self::error::Error;
use ethabi::Interface;


/// Contract specification
#[derive(Clone, Debug, Deserialize)]
pub struct Contract {
    abi: Interface,
}
