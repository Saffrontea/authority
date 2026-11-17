//! Shared wire-level bounds and audience identifiers. Changing their meaning
//! requires contract compatibility review; deployment defaults do not belong here.

pub const CONTRACT_VERSION_V1: &str = "1";
pub const CONTRACT_VERSION_V2: &str = "2";
pub const SIGNATURE_ALGORITHM_ED25519: &str = "Ed25519";
pub const PLAN_SELECTION_RULE_V1: &str = "fewest_mechanisms_then_candidate_id";
pub const MIN_TTL_SECONDS: i64 = 1;
pub const MAX_TTL_SECONDS: i64 = 600;
pub const MAX_TCP_PORTS: usize = 64;
pub const MAX_PLAN_MECHANISMS_V1: usize = 5;
pub const MAX_PLAN_CANDIDATES_V1: usize = 2;
pub const PLANNING_EVIDENCE_VERSION_V1: u8 = 1;

pub const CREDENTIAL_ISSUER_AUDIENCE: &str = "credential-issuer";
pub const NODE_AGENT_AUDIENCE: &str = "node-agent";
pub const NETWORK_AGENT_AUDIENCE: &str = "network-agent";

#[must_use]
pub const fn valid_ttl_seconds(seconds: i64) -> bool {
    seconds >= MIN_TTL_SECONDS && seconds <= MAX_TTL_SECONDS
}

#[must_use]
pub fn domain_issuer(domain_id: impl std::fmt::Display) -> String {
    format!("domain-authority:{domain_id}")
}
