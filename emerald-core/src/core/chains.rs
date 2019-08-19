use std::str::FromStr;

/// Ethereum Chain Reference
pub enum Chain {
    /// Ethereum
    Ethereum,
    /// Morden Testnet
    Morden,
    /// Ethereum Classic
    EthereumClassic,
    /// Kovan Testnet
    Kovan,
    /// Rootstock
    Rootstock,
    /// Rootstock Testnet
    RootstockTestnet,
    /// Rinkeby Testnet
    Rinkeby,
    /// Morden Testnet configured for Ethereum Classic
    MordenClassic,
    /// Ropsten Testnet
    Ropsten,
}

impl FromStr for Chain {

    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.to_lowercase();
        match clean.as_str() {
            "eth" | "ethereum" | "eth-mainnet" => Ok(Chain::Ethereum),
            "morden" => Ok(Chain::Morden),
            "ropsten" => Ok(Chain::Ropsten),
            "rinkeby" => Ok(Chain::Rinkeby),
            "rootstock-main" => Ok(Chain::Rootstock),
            "rootstock-test" => Ok(Chain::RootstockTestnet),
            "kovan" => Ok(Chain::Kovan),
            "mainnet" | "etc-mainnet" | "etc" | "ethereum-classic" | "ethereum classic" => Ok(Chain::EthereumClassic),
            "etc-morden" => Ok(Chain::MordenClassic),
            _ => Err(())
        }
    }
}

impl Chain {

    pub fn get_all_paths() -> [String; 8] {
        [
            Chain::Ethereum.get_path_element(),
            Chain::Morden.get_path_element(),
            Chain::Ropsten.get_path_element(),
            Chain::Rinkeby.get_path_element(),
            Chain::Rootstock.get_path_element(),
            Chain::RootstockTestnet.get_path_element(),
            Chain::Kovan.get_path_element(),
            Chain::EthereumClassic.get_path_element(),
        ]
    }

    /// Try to find Chain by provided chain_id
    ///
    pub fn from_chain_id(id: u8) -> Result<Self, (u8)> {
        match id {
            1 => Ok(Chain::Ethereum),
            2 => Ok(Chain::Morden),
            3 => Ok(Chain::Ropsten),
            4 => Ok(Chain::Rinkeby),
            30 => Ok(Chain::Rootstock),
            31 => Ok(Chain::RootstockTestnet),
            42 => Ok(Chain::Kovan),
            61 => Ok(Chain::EthereumClassic),
            62 => Ok(Chain::MordenClassic),
            id => Err(id)
        }
    }

    /// chain_id for current Chain
    pub fn get_chain_id(&self) -> u8 {
        match self {
            Chain::Ethereum => 1,
            Chain::Morden => 2,
            Chain::Ropsten => 3,
            Chain::Rinkeby => 4,
            Chain::Rootstock => 30,
            Chain::RootstockTestnet => 31,
            Chain::Kovan => 42,
            Chain::EthereumClassic => 61,
            Chain::MordenClassic => 62,
        }
    }

    /// Storage path element for current Chain
    pub fn get_path_element(&self) -> String {
        match self {
            Chain::Ethereum => "eth".to_string(),
            Chain::Morden => "morden".to_string(),
            Chain::Ropsten => "ropsten".to_string(),
            Chain::Rinkeby => "rinkeby".to_string(),
            Chain::Rootstock => "rootstock-main".to_string(),
            Chain::RootstockTestnet => "rootstock-test".to_string(),
            Chain::Kovan => "kovan".to_string(),
            Chain::EthereumClassic => "mainnet".to_string(),
            Chain::MordenClassic => "morden".to_string(),
        }
    }

    /// code for current Chain
    pub fn get_code(&self) -> String {
        match self {
            Chain::EthereumClassic => "etc".to_string(),
            x => x.get_path_element()
        }
    }

    /// Check if chain is a testnet
    pub fn is_testnet(&self) -> bool {
        match self {
            Chain::Ethereum => false,
            Chain::Morden => true,
            Chain::Ropsten => true,
            Chain::Rinkeby => true,
            Chain::Rootstock => false,
            Chain::RootstockTestnet => true,
            Chain::Kovan => true,
            Chain::EthereumClassic => false,
            Chain::MordenClassic => true,
        }
    }
}
