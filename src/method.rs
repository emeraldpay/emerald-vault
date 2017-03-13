use jsonrpc_core::Params;

pub enum Method<'a> {
    ClientVersion,
    EthSyncing,
    EthBlockNumber,
    EthAccounts,
    EthGetBalance(&'a Params),
}
