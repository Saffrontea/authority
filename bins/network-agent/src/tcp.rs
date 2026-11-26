use authority_contracts_model::TcpAccessGrantV2;
use std::fmt::Write as _;
use std::{
    collections::HashMap,
    io::Write,
    process::{Child, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct TcpAdmission {
    pub ports: authority_contracts_model::resources::PortSet,
    pub grants: HashMap<String, TcpAccessGrantV2>,
}

impl TcpAdmission {
    pub fn revoke_many(
        &mut self,
        decisions: &std::collections::HashSet<String>,
    ) -> Result<(), String> {
        let previous = self.grants.clone();
        self.grants.retain(|id, _| !decisions.contains(id));
        if let Err(cause) = self.sync() {
            self.grants = previous;
            return Err(cause);
        }
        Ok(())
    }
    pub fn initialize(
        interface: &str,
        ports: authority_contracts_model::resources::PortSet,
    ) -> Result<Self, String> {
        let exists = super::bounded_command("/usr/sbin/nft")
            .args(["list", "table", "inet", "authority_tcp"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?
            .success();
        let delete = if exists {
            "delete table inet authority_tcp\n"
        } else {
            ""
        };
        let ports_text = ports
            .intervals()
            .iter()
            .map(|range| render_port(*range))
            .collect::<Vec<_>>()
            .join(", ");
        let rules = format!(
            r#"{delete}add table inet authority_tcp
add set inet authority_tcp allowed {{ type ipv4_addr . ipv4_addr . inet_service; flags interval, timeout; }}
add chain inet authority_tcp inbound {{ type filter hook input priority -10; policy accept; }}
add chain inet authority_tcp outbound {{ type filter hook output priority -10; policy accept; }}
add rule inet authority_tcp inbound iifname "{interface}" tcp dport {{ {ports_text} }} ip saddr . ip daddr . tcp dport @allowed counter accept
add rule inet authority_tcp inbound iifname "{interface}" tcp dport {{ {ports_text} }} counter reject with tcp reset
add rule inet authority_tcp outbound oifname "{interface}" tcp sport {{ {ports_text} }} ip daddr . ip saddr . tcp sport @allowed counter accept
add rule inet authority_tcp outbound oifname "{interface}" tcp sport {{ {ports_text} }} counter reject with tcp reset
"#
        );
        nft(&rules)?;
        Ok(Self {
            ports,
            grants: HashMap::new(),
        })
    }

    pub fn apply(&mut self, grant: TcpAccessGrantV2, now: i64) -> Result<(), String> {
        self.grants.retain(|_, grant| grant.expires_at > now);
        if self.grants.len() >= 1024 {
            return Err("TCP grant capacity reached".to_owned());
        }
        if !grant.resources.destination_ports.is_subset(&self.ports) {
            return Err("TCP grant requests an unmanaged port".to_owned());
        }
        let decision = grant.decision_id.clone();
        self.grants.insert(decision.clone(), grant);
        if let Err(error) = self.sync() {
            self.grants.remove(&decision);
            return Err(error);
        }
        Ok(())
    }

    pub fn revoke(&mut self, decision_id: &str) -> Result<bool, String> {
        let removed = self.grants.remove(decision_id);
        if let Err(error) = self.sync() {
            if let Some(grant) = removed {
                self.grants.insert(decision_id.to_owned(), grant);
            }
            return Err(error);
        }
        Ok(removed.is_some())
    }

    pub fn clear(&mut self) -> Result<(), String> {
        let previous = std::mem::take(&mut self.grants);
        if let Err(cause) = self.sync() {
            self.grants = previous;
            return Err(cause);
        }
        Ok(())
    }

    pub(super) fn sync(&self) -> Result<(), String> {
        let now_ms = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis(),
        )
        .map_err(|e| e.to_string())?;
        nft(&rules_for_grants(self.grants.values(), now_ms)?)
    }
}

fn render_port(interval: authority_contracts_model::resources::Interval) -> String {
    if interval.end == interval.start + 1 {
        interval.start.to_string()
    } else {
        format!("{}-{}", interval.start, interval.end - 1)
    }
}
fn render_address(
    interval: authority_contracts_model::resources::Interval,
) -> Result<String, String> {
    let first = std::net::Ipv4Addr::from(u32::try_from(interval.start).map_err(|e| e.to_string())?);
    let last =
        std::net::Ipv4Addr::from(u32::try_from(interval.end - 1).map_err(|e| e.to_string())?);
    Ok(if first == last {
        first.to_string()
    } else {
        format!("{first}-{last}")
    })
}

fn rules_for_grants<'a>(
    grants: impl Iterator<Item = &'a TcpAccessGrantV2>,
    now_ms: i64,
) -> Result<String, String> {
    use authority_contracts_model::resources::{MAX_INTERVALS, uncovered};
    let mut grants: Vec<_> = grants
        .filter(|grant| grant.expires_at.saturating_mul(1000) > now_ms)
        .collect();
    grants.sort_by(|left, right| {
        right
            .expires_at
            .cmp(&left.expires_at)
            .then_with(|| left.decision_id.cmp(&right.decision_id))
    });
    let mut covered = Vec::new();
    let mut elements = Vec::new();
    for grant in grants {
        let region = grant.resources.region();
        let pieces = uncovered(&region, &covered, MAX_INTERVALS).map_err(|e| e.to_string())?;
        let remaining = grant.expires_at.saturating_mul(1000).saturating_sub(now_ms);
        for piece in pieces {
            let count = piece
                .0
                .iter()
                .try_fold(1_usize, |count, axis| {
                    count.checked_mul(axis.intervals().len())
                })
                .ok_or("nft interval product overflow")?;
            if elements.len().saturating_add(count) > MAX_INTERVALS {
                return Err("nft symbolic element budget exhausted".into());
            }
            for source in piece.0[0].intervals() {
                for target in piece.0[1].intervals() {
                    for port in piece.0[2].intervals() {
                        elements.push(format!(
                            "{} . {} . {} timeout {remaining}ms",
                            render_address(*source)?,
                            render_address(*target)?,
                            render_port(*port)
                        ));
                    }
                }
            }
        }
        covered.push(region);
    }
    let mut script = "flush set inet authority_tcp allowed\n".to_owned();
    if !elements.is_empty() {
        writeln!(
            script,
            "add element inet authority_tcp allowed {{ {} }}",
            elements.join(", ")
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(script)
}

fn nft(script: &str) -> Result<(), String> {
    let child = super::bounded_command("/usr/sbin/nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    finish_script(child, script)
}

fn finish_script(mut child: Child, script: &str) -> Result<(), String> {
    let written = match child.stdin.take() {
        Some(mut input) => input
            .write_all(script.as_bytes())
            .map_err(|error| error.to_string()),
        None => Err("missing nft stdin".into()),
    };
    // Always reap, including a timeout or an early stdin close. The external
    // deadline also bounds a child that never drains its input pipe.
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    written?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(decision: &str, expiry: i64) -> TcpAccessGrantV2 {
        let mut grant: TcpAccessGrantV2 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/tcp-access-grant-v2/valid/basic.json"
        ))
        .unwrap();
        grant.decision_id = decision.to_owned();
        grant.expires_at = expiry;
        grant
    }

    #[test]
    fn closed_stdin_still_reaps_the_failed_child() {
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "exec 0<&-; exit 0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(finish_script(child, &"x".repeat(128 * 1024)).is_err());
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "failed actuator child was not reaped"
        );
    }

    #[test]
    fn overlapping_grants_keep_the_longest_deadline_without_refreshing_it() {
        let first = grant("first", 110);
        let second = grant("second", 120);
        let rules = rules_for_grants([&first, &second].into_iter(), 100_500).unwrap();
        assert!(rules.contains("10.77.0.1 . 10.77.0.2 . 8080 timeout 19500ms"));
        assert_eq!(rules.matches("timeout").count(), 1);
        let after_revoking_second = rules_for_grants([&first].into_iter(), 101_000).unwrap();
        assert!(after_revoking_second.contains("timeout 9000ms"));
        assert!(!after_revoking_second.contains("19000ms"));
        assert_eq!(
            rules_for_grants([&first].into_iter(), 110_000).unwrap(),
            "flush set inet authority_tcp allowed\n"
        );
    }
    #[test]
    fn cidr_and_full_port_range_compile_without_point_expansion() {
        let mut wide = grant("wide", 120);
        wide.resources.source_addresses = "10.0.0.0/8".parse().unwrap();
        wide.resources.destination_addresses = "192.168.0.0/16".parse().unwrap();
        wide.resources.destination_ports = "1024-65535".parse().unwrap();
        let script = rules_for_grants([&wide].into_iter(), 100_000).unwrap();
        assert!(script.contains(
            "10.0.0.0-10.255.255.255 . 192.168.0.0-192.168.255.255 . 1024-65535 timeout 20000ms"
        ));
        assert_eq!(script.matches("timeout").count(), 1);
        assert!(script.len() < 256);
        let mut narrow = grant("narrow", 130);
        narrow.resources.source_addresses = "10.0.0.1".parse().unwrap();
        narrow.resources.destination_addresses = "192.168.0.1".parse().unwrap();
        let script = rules_for_grants([&wide, &narrow].into_iter(), 100_000).unwrap();
        assert!(script.contains("10.0.0.1 . 192.168.0.1 . 8080 timeout 30000ms"));
        assert!(script.len() < 1024);
    }
}
