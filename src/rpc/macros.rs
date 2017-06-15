macro_rules! parse_params {
    ( $p:ident : $t:ty ) => (
        let $p: Result<$t, JsonRpcError> = $p.parse();
        if $p.is_err() {
            return futures::failed($p.err().unwrap()).boxed();
        }
        let $p = $p.unwrap();
    );
}

macro_rules! put_result {
    ( $p:expr ) => (
        let value = to_value($p);
        if value.is_err() {
            return futures::failed(JsonRpcError::internal_error()).boxed();
        }
        return futures::finished(value.unwrap()).boxed();
    )
}

macro_rules! put_error {
    ( $p:expr ) => (
        return futures::failed($p).boxed();
    )
}
