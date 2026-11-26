//! Interpret access scopes as products; policy precedence has no protocol cases.
use crate::resources::{Interval, IntervalSet, ResourceError};
use crate::{
    realization::Ability,
    scoped::{AbilityScope, AccessBinding, ScopedAbility},
};
use authority_planning_core::authority::{Domain, Product};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Axis {
    Numeric(IntervalSet),
    Symbols(BTreeSet<String>),
}
impl Domain for Axis {
    type Error = ResourceError;
    fn is_empty(&self) -> bool {
        match self {
            Self::Numeric(s) => s.is_empty(),
            Self::Symbols(s) => s.is_empty(),
        }
    }
    fn intersection(&self, other: &Self) -> Result<Self, ResourceError> {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.intersection(b).map(Self::Numeric),
            (Self::Symbols(a), Self::Symbols(b)) => {
                Ok(Self::Symbols(a.intersection(b).cloned().collect()))
            }
            _ => Err(ResourceError::Invalid),
        }
    }
    fn difference(&self, other: &Self) -> Result<Self, ResourceError> {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.difference(b).map(Self::Numeric),
            (Self::Symbols(a), Self::Symbols(b)) => {
                Ok(Self::Symbols(a.difference(b).cloned().collect()))
            }
            _ => Err(ResourceError::Invalid),
        }
    }
    fn complexity(&self) -> usize {
        match self {
            Self::Numeric(s) => s.intervals().len(),
            Self::Symbols(s) => s.len(),
        }
    }
}
pub type Identity = (AccessBinding, Ability);
pub type Authority = (Identity, Product<Axis>);
fn symbol(s: &str) -> Axis {
    Axis::Symbols(BTreeSet::from([s.to_owned()]))
}

/// Convert without expanding ports, addresses, principals, or time into points.
///
/// # Errors
/// Rejects invalid scope or lifetime rather than constructing an empty authority.
pub fn authority(ability: &ScopedAbility) -> Result<Authority, ResourceError> {
    if !ability.contains(ability) {
        return Err(ResourceError::Invalid);
    }
    let mut axes = match &ability.scope {
        AbilityScope::MeshMembership {
            wireguard_public_key,
            address,
        } => vec![symbol(wireguard_public_key), symbol(&address.to_string())],
        AbilityScope::NetworkRouteAuthorization {
            source,
            destination,
        }
        | AbilityScope::NetworkReachability {
            source,
            destination,
        } => vec![
            Axis::Numeric(source.as_set().clone()),
            Axis::Numeric(destination.as_set().clone()),
        ],
        AbilityScope::TcpAdmission {
            source,
            destination,
            ports,
        }
        | AbilityScope::TcpConnection {
            source,
            destination,
            ports,
        } => vec![
            Axis::Numeric(source.as_set().clone()),
            Axis::Numeric(destination.as_set().clone()),
            Axis::Numeric(ports.as_set().clone()),
        ],
        AbilityScope::SshCredential {
            public_key_fingerprint,
            principals,
            terminal_token_hash,
        }
        | AbilityScope::SshSession {
            public_key_fingerprint,
            principals,
            terminal_token_hash,
        } => vec![
            symbol(public_key_fingerprint),
            Axis::Symbols(principals.clone()),
            symbol(terminal_token_hash),
        ],
        AbilityScope::MtlsCredential {
            client_spki_sha256,
            identity_uri,
            service_audience,
        }
        | AbilityScope::ServiceIdentity {
            client_spki_sha256,
            identity_uri,
            service_audience,
        } => vec![
            symbol(client_spki_sha256),
            symbol(identity_uri),
            symbol(service_audience),
        ],
    };
    axes.push(Axis::Numeric(IntervalSet::new(vec![Interval {
        start: u64::try_from(ability.validity.not_before).map_err(|_| ResourceError::Invalid)?,
        end: u64::try_from(ability.validity.expires_at).map_err(|_| ResourceError::Invalid)?,
    }])?));
    Ok(((ability.binding, ability.scope.kind()), Product(axes)))
}
