use jsonrpc_core::Params;

pub enum Method<'a> {
    ClientVersion(&'a Params),
    EthSyncing(&'a Params),
    EthBlockNumber(&'a Params),
    EthAccounts(&'a Params),
    EthGetBalance(&'a Params),
}
