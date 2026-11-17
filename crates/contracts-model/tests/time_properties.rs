use authority_contracts_model::{
    IssuanceAuthorizationV1, MtlsIssuanceAuthorizationV1, NetworkAccessGrantV1, TcpAccessGrantV1,
    protocol::lifetime_seconds,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn lifetime_and_contract_validators_match_integer_time_spec(
        (issued, start, end) in prop_oneof![
            (any::<i64>(), any::<i64>(), any::<i64>()),
            (any::<i64>(), 1_i64..=700).prop_map(|(start, ttl)| (start, start, start.saturating_add(ttl))),
            Just((i64::MIN, i64::MIN, i64::MAX)),
        ],
    ) {
        let delta = i128::from(end) - i128::from(start);
        let lifetime_ok = (1..=600).contains(&delta);
        prop_assert_eq!(lifetime_seconds(start, end).is_some(), lifetime_ok);
        if let Some(seconds) = lifetime_seconds(start, end) {
            prop_assert_eq!(i128::from(seconds), delta);
        }
        let expected = issued <= start && lifetime_ok;
        let mut ssh: IssuanceAuthorizationV1 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/issuance-authorization-v1/valid/basic.json")).unwrap();
        ssh.issued_at = issued; ssh.not_before = start; ssh.expires_at = end;
        prop_assert_eq!(ssh.validate().is_ok(), expected);
        let mut network: NetworkAccessGrantV1 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/network-access-grant-v1/valid/basic.json")).unwrap();
        network.issued_at = issued; network.not_before = start; network.expires_at = end;
        prop_assert_eq!(network.validate().is_ok(), expected);
        let mut mtls: MtlsIssuanceAuthorizationV1 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/mtls-issuance-authorization-v1/valid/basic.json")).unwrap();
        mtls.issued_at = issued; mtls.not_before = start; mtls.expires_at = end;
        prop_assert_eq!(mtls.validate().is_ok(), expected);
        let mut tcp: TcpAccessGrantV1 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/tcp-access-grant-v1/valid/basic.json")).unwrap();
        tcp.issued_at = issued; tcp.not_before = start; tcp.expires_at = end;
        prop_assert_eq!(tcp.validate().is_ok(), expected);
    }
}
