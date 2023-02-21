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
    /// Goerli Testnet
    Goerli,
    Custom(u8)
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
    GoerliTestnet = 10005
}

impl Blockchain {
    pub fn get_type(&self) -> BlockchainType {
        match self {
            Blockchain::BitcoinTestnet | Blockchain::Bitcoin => BlockchainType::Bitcoin,
            Blockchain::Ethereum | Blockchain::EthereumClassic | Blockchain::KovanTestnet | Blockchain::GoerliTestnet => {
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

    pub fn is_mainnet(&self) -> bool {
        match self {
            Blockchain::Bitcoin | Blockchain::Ethereum | Blockchain::EthereumClassic => true,
            _ => false
        }
    }
}

impl From<Blockchain> for EthereumChainId {
    fn from(blockchain: Blockchain) -> Self {
        match blockchain {
            Blockchain::Ethereum => EthereumChainId::Ethereum,
            Blockchain::EthereumClassic => EthereumChainId::EthereumClassic,
            Blockchain::KovanTestnet => EthereumChainId::Kovan,
            Blockchain::GoerliTestnet => EthereumChainId::Goerli,
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
            EthereumChainId::Goerli => Ok(Blockchain::GoerliTestnet),
            _ => panic!("custom ethereum blockchain"),
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
            10005 => Ok(Blockchain::GoerliTestnet),
            _ => Err(()),
        }
    }
}

impl Into<u32> for Blockchain {
    fn into(self) -> u32 {
        (self as isize) as u32
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
            "goerli" => Ok(EthereumChainId::Goerli),
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
            EthereumChainId::Goerli => 5,
            EthereumChainId::Custom(v) => *v
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::blockchain::chains::{Blockchain};
    use std::convert::TryFrom;
    use std::convert::Into;

    #[test]
    fn convert_blockchain_into_u32() {
        assert_eq!(
            100,
            Into::<u32>::into(Blockchain::Ethereum)
        );
        assert_eq!(
            101,
            Into::<u32>::into(Blockchain::EthereumClassic)
        );

        assert_eq!(
            1,
            Into::<u32>::into(Blockchain::Bitcoin)
        );
    }

    #[test]
    fn convert_blockchain_into_u32_and_opposite() {
        assert_eq!(
            Blockchain::Ethereum,
            Blockchain::try_from(Into::<u32>::into(Blockchain::Ethereum)).unwrap()
        );

        assert_eq!(
            Blockchain::EthereumClassic,
            Blockchain::try_from(Into::<u32>::into(Blockchain::EthereumClassic)).unwrap()
        );

        assert_eq!(
            Blockchain::GoerliTestnet,
            Blockchain::try_from(Into::<u32>::into(Blockchain::GoerliTestnet)).unwrap()
        );

        assert_eq!(
            Blockchain::Bitcoin,
            Blockchain::try_from(Into::<u32>::into(Blockchain::Bitcoin)).unwrap()
        );

        assert_eq!(
            Blockchain::BitcoinTestnet,
            Blockchain::try_from(Into::<u32>::into(Blockchain::BitcoinTestnet)).unwrap()
        );
    }
}
