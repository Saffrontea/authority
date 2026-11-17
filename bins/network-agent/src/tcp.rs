use authority_contracts_model::TcpAccessGrantV1;
use std::fmt::Write as _;
use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct TcpAdmission {
    pub ports: Vec<u16>,
    pub grants: HashMap<String, TcpAccessGrantV1>,
}

impl TcpAdmission {
    pub fn initialize(interface: &str, ports: Vec<u16>) -> Result<Self, String> {
        let exists = Command::new("/usr/sbin/nft")
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
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let rules = format!(
            r#"{delete}add table inet authority_tcp
add set inet authority_tcp allowed {{ type ipv4_addr . ipv4_addr . inet_service; flags timeout; }}
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

    pub fn apply(&mut self, grant: TcpAccessGrantV1, now: i64) -> Result<(), String> {
        self.grants.retain(|_, grant| grant.expires_at > now);
        if self.grants.len() >= 1024 {
            return Err("TCP grant capacity reached".to_owned());
        }
        if grant
            .destination_ports
            .iter()
            .any(|port| !self.ports.contains(port))
        {
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

    fn sync(&self) -> Result<(), String> {
        let now_ms = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis(),
        )
        .map_err(|e| e.to_string())?;
        nft(&rules_for_grants(self.grants.values(), now_ms))
    }
}

fn rules_for_grants<'a>(grants: impl Iterator<Item = &'a TcpAccessGrantV1>, now_ms: i64) -> String {
    let mut entries = BTreeMap::new();
    for grant in grants {
        for port in &grant.destination_ports {
            let key = (&grant.source_address, &grant.destination_address, *port);
            entries
                .entry(key)
                .and_modify(|expiry: &mut i64| *expiry = (*expiry).max(grant.expires_at))
                .or_insert(grant.expires_at);
        }
    }
    let elements = entries
        .into_iter()
        .filter_map(|((source, target, port), expiry)| {
            let remaining = expiry.saturating_mul(1000).saturating_sub(now_ms);
            (remaining > 0).then(|| format!("{source} . {target} . {port} timeout {remaining}ms"))
        })
        .collect::<Vec<_>>();
    let mut script = "flush set inet authority_tcp allowed\n".to_owned();
    if !elements.is_empty() {
        writeln!(
            script,
            "add element inet authority_tcp allowed {{ {} }}",
            elements.join(", ")
        )
        .expect("write String");
    }
    script
}

fn nft(script: &str) -> Result<(), String> {
    let mut child = Command::new("/usr/sbin/nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut input = child.stdin.take().ok_or("missing nft stdin")?;
    input
        .write_all(script.as_bytes())
        .map_err(|e| e.to_string())?;
    drop(input);
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(decision: &str, expiry: i64) -> TcpAccessGrantV1 {
        let mut grant: TcpAccessGrantV1 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/tcp-access-grant-v1/valid/basic.json"
        ))
        .unwrap();
        grant.decision_id = decision.to_owned();
        grant.expires_at = expiry;
        grant
    }

    #[test]
    fn overlapping_grants_keep_the_longest_deadline_without_refreshing_it() {
        let first = grant("first", 110);
        let second = grant("second", 120);
        let rules = rules_for_grants([&first, &second].into_iter(), 100_500);
        assert!(rules.contains("10.77.0.1 . 10.77.0.2 . 8080 timeout 19500ms"));
        assert_eq!(rules.matches("timeout").count(), 1);
        let after_revoking_second = rules_for_grants([&first].into_iter(), 101_000);
        assert!(after_revoking_second.contains("timeout 9000ms"));
        assert!(!after_revoking_second.contains("19000ms"));
        assert_eq!(
            rules_for_grants([&first].into_iter(), 110_000),
            "flush set inet authority_tcp allowed\n"
        );
    }
}
