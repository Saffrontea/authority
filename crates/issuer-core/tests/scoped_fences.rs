use authority_contracts_model::{
    AdapterGrantKindV1,
    fence::{GenerationBinding, RevocationSelector, ScopedRevocationNoticeV3},
};
use authority_issuer_core::{AuthorizationSigner, AuthorizationVerifier, CryptoError, fence};

// Deliberately transparent signer: tests assert that verification covers every
// changed field, independently of the production OpenSSL cryptographic adapter.
struct Signer;
impl AuthorizationSigner for Signer {
    fn key_id(&self) -> &'static str {
        "test"
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(digest(message).to_vec())
    }
}
impl AuthorizationVerifier for Signer {
    fn verify(&self, key: &str, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(key == "test" && signature == digest(message))
    }
}

fn digest(bytes: &[u8]) -> [u8; 64] {
    // Not cryptography: deterministic field-sensitive test double only.
    let mut result = [0_u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        result[i % 64] = result[i % 64].wrapping_mul(31).wrapping_add(*b);
    }
    result
}

fn notice() -> ScopedRevocationNoticeV3 {
    ScopedRevocationNoticeV3 {
        version: 3,
        issuer: "cp".into(),
        domain_id: "domain".into(),
        target_node_id: "target".into(),
        selector: RevocationSelector::Subject {
            subject_user_id: "alice".into(),
            minimum_generation: 2,
        },
        reason: "compromised".into(),
        sequence: 1,
        revoked_at: 100,
        expires_at: 200,
        adapter_kinds: vec![AdapterGrantKindV1::WireGuardPeer],
    }
}

#[test]
fn selectors_bind_generation_domain_target_adapter_and_delivery_window() {
    let signed = fence::sign(notice(), &Signer).unwrap();
    let adapter = AdapterGrantKindV1::WireGuardPeer;
    assert!(fence::verify(&signed, &Signer, "domain", "target", adapter, 100).is_ok());
    for (domain, target, kind, time) in [
        ("other", "target", adapter, 100),
        ("domain", "other", adapter, 100),
        ("domain", "target", AdapterGrantKindV1::TcpPort, 100),
        ("domain", "target", adapter, 99),
        ("domain", "target", adapter, 200),
    ] {
        assert!(fence::verify(&signed, &Signer, domain, target, kind, time).is_err());
    }
    for change in 0..7 {
        let mut altered = signed.clone();
        match change {
            0 => {
                altered.notice.selector = RevocationSelector::Subject {
                    subject_user_id: "bob".into(),
                    minimum_generation: 2,
                }
            }
            1 => {
                altered.notice.selector = RevocationSelector::Subject {
                    subject_user_id: "alice".into(),
                    minimum_generation: 3,
                }
            }
            2 => {
                altered.notice.selector = RevocationSelector::Device {
                    device_id: "alice".into(),
                    minimum_generation: 2,
                }
            }
            3 => altered.notice.reason = "other".into(),
            4 => altered.notice.sequence += 1,
            5 => altered.notice.expires_at += 1,
            _ => altered.key_id = "other".into(),
        }
        assert!(fence::verify(&altered, &Signer, "domain", "target", adapter, 100).is_err());
    }
    let binding = GenerationBinding {
        domain_id: "domain".into(),
        subject_user_id: "alice".into(),
        device_id: "laptop".into(),
        subject_generation: 1,
        device_generation: 1,
    };
    assert!(
        signed
            .notice
            .selector
            .rejects("domain", &binding, "decision")
    );
    assert!(
        !signed
            .notice
            .selector
            .rejects("other", &binding, "decision")
    );
    let mut current = binding;
    current.subject_generation = 2;
    assert!(
        !signed
            .notice
            .selector
            .rejects("domain", &current, "decision")
    );
}

#[test]
fn ambiguous_selectors_and_duplicate_adapters_are_rejected() {
    for input in [
        r#"{"kind":"subject","subject_user_id":"alice","minimum_generation":0}"#,
        r#"{"kind":"future","subject_user_id":"alice","minimum_generation":2}"#,
        r#"{"kind":"subject","subject_user_id":"alice","minimum_generation":2,"device_id":"laptop"}"#,
    ] {
        let parsed = serde_json::from_str::<RevocationSelector>(input);
        assert!(parsed.is_err() || parsed.unwrap().validate().is_err());
    }
    let mut invalid = notice();
    invalid.adapter_kinds.push(invalid.adapter_kinds[0]);
    assert!(invalid.validate().is_err());
}
