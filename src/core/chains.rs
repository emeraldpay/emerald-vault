use std::str::FromStr;
use std::convert::TryFrom;

/// Ethereum Chain Id Reference
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EthereumChainId {
    /// Ethereum
    Ethereum,
    /// Morden Testnet
    Morden,
    /// Ethereum Classic
    EthereumClassic,
    /// Kovan Testnet
    Kovan,
    #[deprecated]
    /// Rootstock
    Rootstock,
    #[deprecated]
    /// Rootstock Testnet
    RootstockTestnet,
    #[deprecated]
    /// Rinkeby Testnet
    Rinkeby,
    /// Morden Testnet configured for Ethereum Classic
    MordenClassic,
    #[deprecated]
    /// Ropsten Testnet
    Ropsten,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Blockchain {
    Ethereum = 100,
    EthereumClassic = 101,
    MordenTestnet = 10001,
    KovanTestnet = 10002
}

impl From<Blockchain> for EthereumChainId {
    fn from(blockchain: Blockchain) -> Self {
        match blockchain {
            Blockchain::Ethereum => EthereumChainId::Ethereum,
            Blockchain::EthereumClassic => EthereumChainId::EthereumClassic,
            Blockchain::MordenTestnet => EthereumChainId::MordenClassic,
            Blockchain::KovanTestnet => EthereumChainId::Kovan
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
            EthereumChainId::Morden=> Ok(Blockchain::MordenTestnet),
            EthereumChainId::MordenClassic => Ok(Blockchain::MordenTestnet),
            _ => Err(())
        }
    }
}

impl TryFrom<u32> for Blockchain {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(Blockchain::Ethereum),
            101 => Ok(Blockchain::EthereumClassic),
            10001 => Ok(Blockchain::MordenTestnet),
            10002 => Ok(Blockchain::KovanTestnet),
            _ => Err(())
        }
    }
}

impl FromStr for EthereumChainId {

    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.to_lowercase();
        match clean.as_str() {
            "eth" | "ethereum" | "eth-mainnet" => Ok(EthereumChainId::Ethereum),
            "morden" => Ok(EthereumChainId::Morden),
            "ropsten" => Ok(EthereumChainId::Ropsten),
            "rinkeby" => Ok(EthereumChainId::Rinkeby),
            "rootstock-main" => Ok(EthereumChainId::Rootstock),
            "rootstock-test" => Ok(EthereumChainId::RootstockTestnet),
            "kovan" => Ok(EthereumChainId::Kovan),
            "mainnet" | "etc-mainnet" | "etc" | "ethereum-classic" | "ethereum classic" => Ok(EthereumChainId::EthereumClassic),
            "etc-morden" => Ok(EthereumChainId::MordenClassic),
            _ => Err(())
        }
    }
}

impl EthereumChainId {

    pub fn get_all_paths() -> [String; 8] {
        [
            EthereumChainId::Ethereum.get_path_element(),
            EthereumChainId::Morden.get_path_element(),
            EthereumChainId::Ropsten.get_path_element(),
            EthereumChainId::Rinkeby.get_path_element(),
            EthereumChainId::Rootstock.get_path_element(),
            EthereumChainId::RootstockTestnet.get_path_element(),
            EthereumChainId::Kovan.get_path_element(),
            EthereumChainId::EthereumClassic.get_path_element(),
        ]
    }

    /// Try to find Chain by provided chain_id
    ///
    pub fn from_chainid(id: u8) -> Result<Self, (u8)> {
        match id {
            1 => Ok(EthereumChainId::Ethereum),
            2 => Ok(EthereumChainId::Morden),
            3 => Ok(EthereumChainId::Ropsten),
            4 => Ok(EthereumChainId::Rinkeby),
            30 => Ok(EthereumChainId::Rootstock),
            31 => Ok(EthereumChainId::RootstockTestnet),
            42 => Ok(EthereumChainId::Kovan),
            61 => Ok(EthereumChainId::EthereumClassic),
            62 => Ok(EthereumChainId::MordenClassic),
            id => Err(id)
        }
    }

    /// chain_id for current Chain
    pub fn as_chainid(&self) -> u8 {
        match self {
            EthereumChainId::Ethereum => 1,
            EthereumChainId::Morden => 2,
            EthereumChainId::Ropsten => 3,
            EthereumChainId::Rinkeby => 4,
            EthereumChainId::Rootstock => 30,
            EthereumChainId::RootstockTestnet => 31,
            EthereumChainId::Kovan => 42,
            EthereumChainId::EthereumClassic => 61,
            EthereumChainId::MordenClassic => 62,
        }
    }

    /// Storage path element for current Chain
    pub fn get_path_element(&self) -> String {
        match self {
            EthereumChainId::Ethereum => "eth".to_string(),
            EthereumChainId::Morden => "morden".to_string(),
            EthereumChainId::Ropsten => "ropsten".to_string(),
            EthereumChainId::Rinkeby => "rinkeby".to_string(),
            EthereumChainId::Rootstock => "rootstock-main".to_string(),
            EthereumChainId::RootstockTestnet => "rootstock-test".to_string(),
            EthereumChainId::Kovan => "kovan".to_string(),
            EthereumChainId::EthereumClassic => "mainnet".to_string(),
            EthereumChainId::MordenClassic => "morden".to_string(),
        }
    }

    /// code for current Chain
    pub fn get_code(&self) -> String {
        match self {
            EthereumChainId::EthereumClassic => "etc".to_string(),
            x => x.get_path_element()
        }
    }

    /// Check if chain is a testnet
    pub fn is_testnet(&self) -> bool {
        match self {
            EthereumChainId::Ethereum => false,
            EthereumChainId::Morden => true,
            EthereumChainId::Ropsten => true,
            EthereumChainId::Rinkeby => true,
            EthereumChainId::Rootstock => false,
            EthereumChainId::RootstockTestnet => true,
            EthereumChainId::Kovan => true,
            EthereumChainId::EthereumClassic => false,
            EthereumChainId::MordenClassic => true,
        }
    }
}
