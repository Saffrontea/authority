//! Pure access-policy evaluation shared by every credential adapter.

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    pub domain_id: Uuid,
    pub subject_user_id: Uuid,
    pub device_id: Uuid,
    pub target_node_id: Uuid,
    pub evaluated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCandidate {
    pub policy_id: Uuid,
    pub domain_id: Uuid,
    pub subject_user_id: Uuid,
    pub required_device_id: Option<Uuid>,
    pub target_node_id: Uuid,
    pub enabled: bool,
    pub effect: Effect,
    pub priority: i32,
    pub revision: i64,
    pub capabilities: Vec<String>,
    pub revoked_at: Option<i64>,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
    pub ssh_principal: String,
    pub device_domain_id: Uuid,
    pub device_owner_user_id: Uuid,
    pub device_active: bool,
    pub target_active: bool,
    pub wireguard_public_key: Vec<u8>,
    pub device_mesh_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    pub policy_id: Uuid,
    pub policy_revision: i64,
    pub domain_id: Uuid,
    pub subject_user_id: Uuid,
    pub device_id: Uuid,
    pub target_node_id: Uuid,
    pub ssh_principal: String,
    pub wireguard_public_key: Vec<u8>,
    pub device_mesh_address: String,
    pub evaluated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    #[error("policy identity scope does not match the request")]
    ScopeMismatch,
    #[error("device identity does not match the authenticated subject")]
    DeviceMismatch,
    #[error("policy requires a different device")]
    RequiredDeviceMismatch,
    #[error("policy, device, or target is disabled")]
    Disabled,
    #[error("policy explicitly denies access")]
    ExplicitDeny,
    #[error("policy does not grant both required adapter capabilities")]
    MissingCapability,
    #[error("policy is outside its validity window")]
    OutsideValidityWindow,
    #[error("policy has no valid SSH principal")]
    InvalidPrincipal,
    #[error("device has no assigned mesh address")]
    MissingMeshAddress,
}

/// Evaluates one repository-provided candidate without knowing its storage.
///
/// # Errors
///
/// Returns a stable denial reason when any common policy invariant fails.
pub fn evaluate(
    request: &AccessRequest,
    candidate: PolicyCandidate,
) -> Result<AccessDecision, DenialReason> {
    if candidate.domain_id != request.domain_id
        || candidate.subject_user_id != request.subject_user_id
        || candidate.target_node_id != request.target_node_id
    {
        return Err(DenialReason::ScopeMismatch);
    }
    if candidate.device_domain_id != request.domain_id
        || candidate.device_owner_user_id != request.subject_user_id
    {
        return Err(DenialReason::DeviceMismatch);
    }
    if candidate
        .required_device_id
        .is_some_and(|id| id != request.device_id)
    {
        return Err(DenialReason::RequiredDeviceMismatch);
    }
    if !candidate.enabled
        || candidate.revoked_at.is_some()
        || !candidate.device_active
        || !candidate.target_active
    {
        return Err(DenialReason::Disabled);
    }
    if candidate
        .valid_from
        .is_some_and(|valid_from| valid_from > request.evaluated_at)
        || candidate
            .valid_until
            .is_some_and(|valid_until| valid_until <= request.evaluated_at)
    {
        return Err(DenialReason::OutsideValidityWindow);
    }
    if candidate.ssh_principal.is_empty() {
        return Err(DenialReason::InvalidPrincipal);
    }
    if !candidate.capabilities.iter().any(|value| value == "ssh")
        || !candidate
            .capabilities
            .iter()
            .any(|value| value == "wireguard")
    {
        return Err(DenialReason::MissingCapability);
    }
    if candidate.effect == Effect::Deny {
        return Err(DenialReason::ExplicitDeny);
    }
    let device_mesh_address = candidate
        .device_mesh_address
        .ok_or(DenialReason::MissingMeshAddress)?;
    Ok(AccessDecision {
        policy_id: candidate.policy_id,
        policy_revision: candidate.revision,
        domain_id: request.domain_id,
        subject_user_id: request.subject_user_id,
        device_id: request.device_id,
        target_node_id: request.target_node_id,
        ssh_principal: candidate.ssh_principal,
        wireguard_public_key: candidate.wireguard_public_key,
        device_mesh_address,
        evaluated_at: request.evaluated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_decision_carries_bindings_for_both_adapters() {
        let (request, candidate) = fixture();
        let decision = evaluate(&request, candidate).expect("allow fixture");
        assert_eq!(decision.ssh_principal, "deploy");
        assert_eq!(decision.wireguard_public_key, b"registered-wg-key");
    }

    #[test]
    fn rejects_wrong_device_and_expired_policy() {
        let (request, mut candidate) = fixture();
        candidate.device_owner_user_id = Uuid::new_v4();
        assert_eq!(
            evaluate(&request, candidate),
            Err(DenialReason::DeviceMismatch)
        );

        let (request, mut candidate) = fixture();
        candidate.valid_until = Some(request.evaluated_at);
        assert_eq!(
            evaluate(&request, candidate),
            Err(DenialReason::OutsideValidityWindow)
        );
    }

    #[test]
    fn rejects_explicit_deny_revocation_and_incomplete_capabilities() {
        let (request, mut candidate) = fixture();
        candidate.effect = Effect::Deny;
        assert_eq!(
            evaluate(&request, candidate),
            Err(DenialReason::ExplicitDeny)
        );

        let (request, mut candidate) = fixture();
        candidate.revoked_at = Some(99);
        assert_eq!(evaluate(&request, candidate), Err(DenialReason::Disabled));

        let (request, mut candidate) = fixture();
        candidate.capabilities = vec!["ssh".to_owned()];
        assert_eq!(
            evaluate(&request, candidate),
            Err(DenialReason::MissingCapability)
        );
    }

    fn fixture() -> (AccessRequest, PolicyCandidate) {
        let domain_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let target_node_id = Uuid::new_v4();
        (
            AccessRequest {
                domain_id,
                subject_user_id: user_id,
                device_id,
                target_node_id,
                evaluated_at: 100,
            },
            PolicyCandidate {
                policy_id: Uuid::new_v4(),
                domain_id,
                subject_user_id: user_id,
                required_device_id: Some(device_id),
                target_node_id,
                enabled: true,
                effect: Effect::Allow,
                priority: 0,
                revision: 1,
                capabilities: vec!["ssh".to_owned(), "wireguard".to_owned()],
                revoked_at: None,
                valid_from: Some(50),
                valid_until: Some(150),
                ssh_principal: "deploy".to_owned(),
                device_domain_id: domain_id,
                device_owner_user_id: user_id,
                device_active: true,
                target_active: true,
                wireguard_public_key: b"registered-wg-key".to_vec(),
                device_mesh_address: Some("10.77.0.1".to_owned()),
            },
        )
    }
}
