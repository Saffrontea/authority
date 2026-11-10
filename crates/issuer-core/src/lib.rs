//! Cryptographic ports and application logic for issuance authorization.

use authority_contracts_model::{
    ContractError, IssuanceAuthorizationV1, NetworkAccessGrantV1, SignedIssuanceAuthorizationV1,
    SignedNetworkAccessGrantV1,
};
use thiserror::Error;

pub trait AuthorizationSigner {
    fn key_id(&self) -> &str;

    /// Signs the exact contract preimage bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the backing key or signer is unavailable.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait AuthorizationVerifier {
    /// Verifies a signature for the named key and exact preimage bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the verification backend cannot complete.
    fn verify(&self, key_id: &str, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("cryptographic adapter failed: {message}")]
pub struct CryptoError {
    pub message: String,
}

#[derive(Debug, Error)]
pub enum AuthorizationEnvelopeError {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("signature is not valid base64url")]
    InvalidSignatureEncoding,
    #[error("authorization signature verification failed")]
    VerificationFailed,
    #[error("network grant audience is not node-agent")]
    InvalidAudience,
    #[error("network grant targets a different node")]
    TargetNodeMismatch,
    #[error("network grant is not active at the supplied time")]
    GrantNotActive,
}

/// Signs a validated authorization using an injected cryptographic adapter.
///
/// # Errors
///
/// Returns an error when contract validation or signing fails.
pub fn sign_authorization(
    authorization: IssuanceAuthorizationV1,
    signer: &impl AuthorizationSigner,
) -> Result<SignedIssuanceAuthorizationV1, AuthorizationEnvelopeError> {
    let preimage = authorization.signing_preimage()?;
    let signature = signer.sign(&preimage)?;
    let envelope = SignedIssuanceAuthorizationV1 {
        authorization,
        algorithm: "Ed25519".to_owned(),
        key_id: signer.key_id().to_owned(),
        signature: encode_base64url(&signature),
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Verifies both contract semantics and the Ed25519 signature.
///
/// # Errors
///
/// Returns an error for malformed contracts, invalid encodings, adapter
/// failures, and signatures that do not verify.
pub fn verify_authorization(
    envelope: &SignedIssuanceAuthorizationV1,
    verifier: &impl AuthorizationVerifier,
) -> Result<(), AuthorizationEnvelopeError> {
    envelope.validate()?;
    let signature = decode_base64url(&envelope.signature)
        .ok_or(AuthorizationEnvelopeError::InvalidSignatureEncoding)?;
    let preimage = envelope.authorization.signing_preimage()?;
    if !verifier.verify(&envelope.key_id, &preimage, &signature)? {
        return Err(AuthorizationEnvelopeError::VerificationFailed);
    }
    Ok(())
}

/// Signs a validated network grant with the control-plane key.
///
/// # Errors
///
/// Returns an error when contract validation or signing fails.
pub fn sign_network_grant(
    grant: NetworkAccessGrantV1,
    signer: &impl AuthorizationSigner,
) -> Result<SignedNetworkAccessGrantV1, AuthorizationEnvelopeError> {
    let preimage = grant.signing_preimage()?;
    let signature = signer.sign(&preimage)?;
    let envelope = SignedNetworkAccessGrantV1 {
        grant,
        algorithm: "Ed25519".to_owned(),
        key_id: signer.key_id().to_owned(),
        signature: encode_base64url(&signature),
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Verifies the network grant shape, preimage, key id, and signature.
///
/// # Errors
///
/// Returns an error for malformed, tampered, or unverifiable grants.
pub fn verify_network_grant(
    envelope: &SignedNetworkAccessGrantV1,
    verifier: &impl AuthorizationVerifier,
) -> Result<(), AuthorizationEnvelopeError> {
    envelope.validate()?;
    let signature = decode_base64url(&envelope.signature)
        .ok_or(AuthorizationEnvelopeError::InvalidSignatureEncoding)?;
    let preimage = envelope.grant.signing_preimage()?;
    if !verifier.verify(&envelope.key_id, &preimage, &signature)? {
        return Err(AuthorizationEnvelopeError::VerificationFailed);
    }
    Ok(())
}

/// Verifies a grant and binds it to one node and one point in time.
///
/// # Errors
///
/// Returns an error when cryptographic verification fails, the grant is for a
/// different consumer or node, or its validity window is not active.
pub fn verify_network_grant_for_node(
    envelope: &SignedNetworkAccessGrantV1,
    verifier: &impl AuthorizationVerifier,
    expected_target_node_id: &str,
    now: i64,
) -> Result<(), AuthorizationEnvelopeError> {
    verify_network_grant(envelope, verifier)?;
    if envelope.grant.audience != "node-agent" {
        return Err(AuthorizationEnvelopeError::InvalidAudience);
    }
    if envelope.grant.target_node_id != expected_target_node_id {
        return Err(AuthorizationEnvelopeError::TargetNodeMismatch);
    }
    if now < envelope.grant.not_before || now >= envelope.grant.expires_at {
        return Err(AuthorizationEnvelopeError::GrantNotActive);
    }
    Ok(())
}

fn encode_base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        }
    }
    output
}

fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    if input.len() % 4 == 1 {
        return None;
    }
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in input.as_bytes().chunks(4) {
        let a = decode_character(chunk[0])?;
        let b = decode_character(chunk[1])?;
        output.push((a << 2) | (b >> 4));
        if chunk.len() > 2 {
            let c = decode_character(chunk[2])?;
            output.push((b << 4) | (c >> 2));
            if chunk.len() > 3 {
                let d = decode_character(chunk[3])?;
                output.push((c << 6) | d);
            }
        }
    }
    Some(output)
}

fn decode_character(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeCrypto {
        key_id: String,
    }

    impl Default for FakeCrypto {
        fn default() -> Self {
            Self {
                key_id: "control-plane-key-1".to_owned(),
            }
        }
    }

    impl AuthorizationSigner for FakeCrypto {
        fn key_id(&self) -> &str {
            &self.key_id
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let mut signature = vec![0_u8; 64];
            for (index, byte) in message.iter().enumerate() {
                signature[index % 64] ^= byte;
            }
            Ok(signature)
        }
    }

    impl AuthorizationVerifier for FakeCrypto {
        fn verify(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, CryptoError> {
            Ok(key_id == self.key_id() && self.sign(message)? == signature)
        }
    }

    #[test]
    fn signed_envelope_round_trips_and_rejects_tampering() {
        let crypto = FakeCrypto::default();
        let mut envelope = sign_authorization(fixture(), &crypto).expect("sign fixture");
        verify_authorization(&envelope, &crypto).expect("verify fixture");
        envelope.authorization.target_node_id = "node_02".to_owned();
        assert!(matches!(
            verify_authorization(&envelope, &crypto),
            Err(AuthorizationEnvelopeError::VerificationFailed)
        ));
    }

    #[test]
    fn network_grant_is_bound_to_target_and_time() {
        let crypto = FakeCrypto::default();
        let envelope = sign_network_grant(network_fixture(), &crypto).expect("sign grant");
        verify_network_grant_for_node(&envelope, &crypto, "node_01", 1_794_326_500)
            .expect("verify active grant");
        assert!(matches!(
            verify_network_grant_for_node(&envelope, &crypto, "node_02", 1_794_326_500),
            Err(AuthorizationEnvelopeError::TargetNodeMismatch)
        ));
        assert!(matches!(
            verify_network_grant_for_node(&envelope, &crypto, "node_01", 1_794_326_700),
            Err(AuthorizationEnvelopeError::GrantNotActive)
        ));
    }

    #[test]
    fn base64url_round_trips_every_remainder() {
        for value in [b"a".as_slice(), b"ab", b"abc", b"abcd", &[0xff; 64]] {
            let encoded = encode_base64url(value);
            assert_eq!(decode_base64url(&encoded).as_deref(), Some(value));
            assert!(!encoded.contains('='));
        }
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

    fn network_fixture() -> NetworkAccessGrantV1 {
        NetworkAccessGrantV1 {
            version: "1".to_owned(),
            issuer: "domain-authority:example".to_owned(),
            domain_id: "domain_example".to_owned(),
            subject_user_id: "user_01".to_owned(),
            device_id: "device_01".to_owned(),
            target_node_id: "node_01".to_owned(),
            wireguard_public_key: "fX5OQRjDxV9YDJAcmAiiLINEuu1d2Bju+Bfh5SlAlX4=".to_owned(),
            mesh_address: "10.77.0.1".to_owned(),
            policy_id: "policy_01".to_owned(),
            nonce: "dGVzdC1ub25jZS0wMTIzNDU2Nzg5YWJjZGVm".to_owned(),
            issued_at: 1_794_326_400,
            not_before: 1_794_326_400,
            expires_at: 1_794_326_700,
            audience: "node-agent".to_owned(),
        }
    }
}
