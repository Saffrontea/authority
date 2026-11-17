//! Strict decoding of stored policy vocabulary, including explicit legacy aliases.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::Capability;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityParseError {
    #[error("policy capabilities must not be empty")]
    Empty,
    #[error("unknown policy capability {0:?}")]
    Unknown(String),
}

/// Decodes an entire policy capability list atomically. Unknown values are never
/// discarded, for either allow or deny rules. No partial grant set is returned.
///
/// # Errors
/// Rejects empty lists and any unsupported spelling, including wildcards.
pub fn parse_capabilities<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<Capability>, CapabilityParseError> {
    let mut grants = BTreeSet::new();
    for value in values {
        match value {
            "ssh" | "ssh.issue" => {
                grants.insert(Capability::SshIssue);
            }
            "wireguard" => {
                grants.insert(Capability::MeshJoin);
                grants.insert(Capability::NetworkReach);
            }
            "mesh.join" => {
                grants.insert(Capability::MeshJoin);
            }
            "network.reach" => {
                grants.insert(Capability::NetworkReach);
            }
            "mtls.issue" => {
                grants.insert(Capability::MtlsIssue);
            }
            "tcp.connect" => {
                grants.insert(Capability::TcpConnect);
            }
            _ => return Err(CapabilityParseError::Unknown(value.to_owned())),
        }
    }
    if grants.is_empty() {
        return Err(CapabilityParseError::Empty);
    }
    Ok(grants)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_names_and_explicit_legacy_aliases_preserve_their_meaning() {
        assert_eq!(
            parse_capabilities(["ssh", "wireguard", "mtls.issue", "tcp.connect"]).unwrap(),
            BTreeSet::from([
                Capability::SshIssue,
                Capability::MeshJoin,
                Capability::NetworkReach,
                Capability::MtlsIssue,
                Capability::TcpConnect
            ])
        );
        assert_eq!(
            parse_capabilities(["mesh.join", "network.reach", "ssh.issue"]).unwrap(),
            parse_capabilities(["wireguard", "ssh"]).unwrap()
        );
    }

    #[test]
    fn unknown_names_never_produce_an_empty_or_partial_rule() {
        for unknown in [
            "ssh.isssue",
            "tcp.conect",
            "*",
            "SSH",
            "ssh.issue ",
            "",
            "future.capability",
        ] {
            assert_eq!(
                parse_capabilities([unknown]),
                Err(CapabilityParseError::Unknown(unknown.into()))
            );
            assert!(parse_capabilities(["ssh.issue", unknown]).is_err());
            assert!(parse_capabilities([unknown, "ssh.issue"]).is_err());
        }
        assert_eq!(parse_capabilities([]), Err(CapabilityParseError::Empty));
    }
}
