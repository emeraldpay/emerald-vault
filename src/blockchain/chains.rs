use std::{convert::TryFrom, str::FromStr};
use bitcoin::Network;

/// Ethereum Chain Id Reference
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EthereumChainId {
    /// Ethereum
    Ethereum,
    /// Ethereum Classic
    EthereumClassic,
    /// Kovan Testnet
    Kovan,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockchainType {
    Bitcoin,
    Ethereum,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Blockchain {
    Bitcoin = 1,
    BitcoinTestnet = 10003,
    Ethereum = 100,
    EthereumClassic = 101,
    KovanTestnet = 10002,
}

impl Blockchain {
    pub fn get_type(&self) -> BlockchainType {
        match self {
            Blockchain::BitcoinTestnet | Blockchain::Bitcoin => BlockchainType::Bitcoin,
            Blockchain::Ethereum | Blockchain::EthereumClassic | Blockchain::KovanTestnet => {
                BlockchainType::Ethereum
            }
        }
    }

    pub fn as_bitcoin_network(&self) -> Network {
        match self {
            Blockchain::Bitcoin => Network::Bitcoin,
            Blockchain::BitcoinTestnet => Network::Testnet,
            _ => Network::Testnet
        }
    }
}

impl From<Blockchain> for EthereumChainId {
    fn from(blockchain: Blockchain) -> Self {
        match blockchain {
            Blockchain::Ethereum => EthereumChainId::Ethereum,
            Blockchain::EthereumClassic => EthereumChainId::EthereumClassic,
            Blockchain::KovanTestnet => EthereumChainId::Kovan,
            _ => panic!("not an ethereum blockchain"),
        }
    }
}

impl TryFrom<EthereumChainId> for Blockchain {
    type Error = ();

    fn try_from(value: EthereumChainId) -> Result<Self, Self::Error> {
        match value {
            EthereumChainId::Ethereum => Ok(Blockchain::Ethereum),
            EthereumChainId::EthereumClassic => Ok(Blockchain::EthereumClassic),
            EthereumChainId::Kovan => Ok(Blockchain::KovanTestnet),
        }
    }
}

impl TryFrom<u32> for Blockchain {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Blockchain::Bitcoin),
            10003 => Ok(Blockchain::BitcoinTestnet),
            100 => Ok(Blockchain::Ethereum),
            101 => Ok(Blockchain::EthereumClassic),
            10002 => Ok(Blockchain::KovanTestnet),
            _ => Err(()),
        }
    }
}

impl FromStr for EthereumChainId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.to_lowercase();
        match clean.as_str() {
            "eth" | "ethereum" | "eth-mainnet" => Ok(EthereumChainId::Ethereum),
            "kovan" => Ok(EthereumChainId::Kovan),
            "etc-mainnet" | "etc" | "ethereum-classic" | "ethereum classic" => {
                Ok(EthereumChainId::EthereumClassic)
            }
            _ => Err(()),
        }
    }
}

impl EthereumChainId {
    /// chain_id for current Chain
    pub fn as_chainid(&self) -> u8 {
        match self {
            EthereumChainId::Ethereum => 1,
            EthereumChainId::Kovan => 42,
            EthereumChainId::EthereumClassic => 61,
        }
    }
}
