use jsonrpc_core::Params;

pub enum Method {
    ClientVersion,
    EthSyncing,
    EthBlockNumber,
    EthAccounts,
    EthGetBalance,
}

pub struct MethodParams<'a>(pub Method, pub &'a Params);
