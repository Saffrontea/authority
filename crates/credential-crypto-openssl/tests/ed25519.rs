use authority_contracts_model::IssuanceAuthorizationV1;
use authority_credential_crypto_openssl::{OpenSslEd25519Signer, OpenSslEd25519Verifier};
use authority_issuer_core::{sign_authorization, verify_authorization};
use openssl::pkey::PKey;

#[test]
fn openssl_signs_verifies_and_rejects_tampering() {
    let key = PKey::generate_ed25519().expect("generate Ed25519 key");
    let private_key = key.private_key_to_pem_pkcs8().expect("encode private key");
    let public_key = key.public_key_to_pem().expect("encode public key");

    let signer = OpenSslEd25519Signer::from_pem("control-plane-key-1", &private_key)
        .expect("load private key");
    let verifier = OpenSslEd25519Verifier::from_pem("control-plane-key-1", &public_key)
        .expect("load public key");
    let mut envelope = sign_authorization(fixture(), &signer).expect("sign authorization");
    verify_authorization(&envelope, &verifier).expect("verify authorization");

    envelope.authorization.device_id = "device_attacker".to_owned();
    assert!(verify_authorization(&envelope, &verifier).is_err());
}

#[test]
fn constructors_reject_non_ed25519_keys() {
    let rsa = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).expect("generate RSA key"))
        .expect("wrap RSA key");
    let private_key = rsa.private_key_to_pem_pkcs8().expect("encode private key");
    let public_key = rsa.public_key_to_pem().expect("encode public key");

    assert!(OpenSslEd25519Signer::from_pem("wrong-key", &private_key).is_err());
    assert!(OpenSslEd25519Verifier::from_pem("wrong-key", &public_key).is_err());
}

fn fixture() -> IssuanceAuthorizationV1 {
    IssuanceAuthorizationV1 {
        version: "1".to_owned(),
        issuer: "domain-authority:example".to_owned(),
        domain_id: "domain_example".to_owned(),
        subject_user_id: "user_01".to_owned(),
        device_id: "device_01".to_owned(),
        target_node_id: "node_01".to_owned(),
        ssh_public_key_fingerprint: "SHA256:AbCdEf0123456789_-".to_owned(),
        principals: vec!["deploy".to_owned()],
        policy_id: "policy_01".to_owned(),
        nonce: "dGVzdC1ub25jZS0wMTIzNDU2Nzg5YWJjZGVm".to_owned(),
        issued_at: 1_794_326_400,
        not_before: 1_794_326_400,
        expires_at: 1_794_326_700,
        audience: "credential-issuer".to_owned(),
    }
}
