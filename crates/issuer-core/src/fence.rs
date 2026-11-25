//! Authentication of selector revocations. Persisted fence lifetime is independent
//! of the signed notice's finite delivery acceptance window.

use authority_contracts_model::{
    AdapterGrantKindV1,
    fence::{ScopedRevocationNoticeV3, SignedScopedRevocationNoticeV3},
};
use authority_device_auth_core::{decode_base64url, encode_base64url};

use crate::{AuthorizationEnvelopeError, AuthorizationSigner, AuthorizationVerifier};

/// # Errors
/// Produces the same CA-signed identity for issuer and node-install authorizations.
pub fn ssh_key_id(
    envelope: &authority_contracts_model::SignedIssuanceAuthorizationV2,
) -> Result<String, AuthorizationEnvelopeError> {
    envelope.validate()?;
    let a = &envelope.authorization;
    let identity = authority_contracts_model::fence::SshCertificateIdentityV2 {
        version: 2,
        generation: envelope.generation.clone(),
        target_node_id: a.target_node_id.clone(),
        decision_id: a.decision_id.clone(),
        issued_at: a.issued_at,
        not_before: a.not_before,
        expires_at: a.expires_at,
    };
    identity.validate()?;
    let bytes = serde_json::to_vec(&identity).map_err(|_| {
        authority_contracts_model::ContractError::InvalidIdentifier("certificate_identity")
    })?;
    Ok(format!("authority-v2:{}", encode_base64url(&bytes)))
}

/// # Errors
/// Signs a validated root management command.
pub fn sign_command(
    command: authority_contracts_model::administration::IdentityRevocationCommandV1,
    signer: &impl AuthorizationSigner,
) -> Result<
    authority_contracts_model::administration::SignedIdentityRevocationCommandV1,
    AuthorizationEnvelopeError,
> {
    let signature = encode_base64url(&signer.sign(&command.signing_preimage()?)?);
    let envelope = authority_contracts_model::administration::SignedIdentityRevocationCommandV1 {
        command,
        algorithm: authority_contracts_model::protocol::SIGNATURE_ALGORITHM_ED25519.into(),
        key_id: signer.key_id().into(),
        signature,
    };
    envelope.validate()?;
    Ok(envelope)
}

/// # Errors
/// Rejects tampering, wrong roots/domains, future commands and expired delivery.
pub fn verify_command(
    envelope: &authority_contracts_model::administration::SignedIdentityRevocationCommandV1,
    verifier: &impl AuthorizationVerifier,
    domain: &str,
    now: i64,
) -> Result<(), AuthorizationEnvelopeError> {
    envelope.validate()?;
    let signature = decode_base64url(&envelope.signature)
        .ok_or(AuthorizationEnvelopeError::InvalidSignatureEncoding)?;
    if !verifier.verify(
        &envelope.key_id,
        &envelope.command.signing_preimage()?,
        &signature,
    )? {
        return Err(AuthorizationEnvelopeError::VerificationFailed);
    }
    if envelope.command.domain_id != domain {
        return Err(AuthorizationEnvelopeError::RevocationTargetNodeMismatch);
    }
    if now < envelope.command.issued_at {
        return Err(AuthorizationEnvelopeError::RevocationNoticeNotActive);
    }
    if now >= envelope.command.expires_at {
        return Err(AuthorizationEnvelopeError::RevocationNoticeExpired);
    }
    Ok(())
}

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

/// A receiver signs this only after persisting its fence and withdrawing access.
/// Binding the complete notice prevents proxy-forged or cross-operation ACKs.
/// # Errors
/// Rejects malformed notices before constructing the application receipt.
pub fn receipt_preimage(
    notice: &ScopedRevocationNoticeV3,
) -> Result<Vec<u8>, authority_contracts_model::ContractError> {
    let mut message = b"AUTHORITY-SCOPED-REVOCATION-APPLIED-V1\0".to_vec();
    message.extend_from_slice(&notice.signing_preimage()?);
    Ok(message)
}
