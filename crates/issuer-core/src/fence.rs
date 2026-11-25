//! Authentication of selector revocations. Persisted fence lifetime is independent
//! of the signed notice's finite delivery acceptance window.

use authority_contracts_model::{
    AdapterGrantKindV1,
    fence::{ScopedRevocationNoticeV3, SignedScopedRevocationNoticeV3},
};
use authority_device_auth_core::{decode_base64url, encode_base64url};

use crate::{AuthorizationEnvelopeError, AuthorizationSigner, AuthorizationVerifier};

/// # Errors
/// Rejects invalid notices and signing failures.
pub fn sign(
    notice: ScopedRevocationNoticeV3,
    signer: &impl AuthorizationSigner,
) -> Result<SignedScopedRevocationNoticeV3, AuthorizationEnvelopeError> {
    let signature = signer.sign(&notice.signing_preimage()?)?;
    let envelope = SignedScopedRevocationNoticeV3 {
        notice,
        algorithm: authority_contracts_model::protocol::SIGNATURE_ALGORITHM_ED25519.into(),
        key_id: signer.key_id().into(),
        signature: encode_base64url(&signature),
    };
    envelope.validate()?;
    Ok(envelope)
}

/// # Errors
/// Rejects tampering, unknown keys, wrong domain/target/adapter and notices outside
/// their delivery window. An already persisted fence must never expire with it.
pub fn verify(
    envelope: &SignedScopedRevocationNoticeV3,
    verifier: &impl AuthorizationVerifier,
    domain: &str,
    target: &str,
    adapter: AdapterGrantKindV1,
    now: i64,
) -> Result<(), AuthorizationEnvelopeError> {
    envelope.validate()?;
    let signature = decode_base64url(&envelope.signature)
        .ok_or(AuthorizationEnvelopeError::InvalidSignatureEncoding)?;
    if !verifier.verify(
        &envelope.key_id,
        &envelope.notice.signing_preimage()?,
        &signature,
    )? {
        return Err(AuthorizationEnvelopeError::VerificationFailed);
    }
    if envelope.notice.domain_id != domain || envelope.notice.target_node_id != target {
        return Err(AuthorizationEnvelopeError::RevocationTargetNodeMismatch);
    }
    if !envelope.notice.adapter_kinds.contains(&adapter) {
        return Err(AuthorizationEnvelopeError::RevocationAdapterMismatch);
    }
    if now < envelope.notice.revoked_at {
        return Err(AuthorizationEnvelopeError::RevocationNoticeNotActive);
    }
    if now >= envelope.notice.expires_at {
        return Err(AuthorizationEnvelopeError::RevocationNoticeExpired);
    }
    Ok(())
}
