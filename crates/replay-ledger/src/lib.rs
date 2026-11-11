use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

const COMPACT_EVERY: usize = 256;

/// A durable, expiry-aware record of consumed signed-envelope nonces.
///
/// `consume` persists and synchronizes a nonce before reporting success, so a
/// process restart cannot make an already accepted authorization reusable.
pub struct ReplayLedger {
    path: PathBuf,
    entries: HashMap<String, i64>,
    writes_since_compaction: usize,
}

impl ReplayLedger {
    /// Opens a ledger and discards records that have already expired at `now`.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger directory or file cannot be read,
    /// created, compacted, or synchronized.
    pub fn open(path: impl Into<PathBuf>, now: i64) -> Result<Self, String> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut entries: HashMap<String, i64> = HashMap::new();
        if path.exists() {
            let file = File::open(&path).map_err(|error| error.to_string())?;
            for line in BufReader::new(file).lines() {
                let line = line.map_err(|error| error.to_string())?;
                let Some((expires_at, nonce)) = line.split_once('\t') else {
                    continue;
                };
                let Ok(expires_at) = expires_at.parse::<i64>() else {
                    continue;
                };
                if expires_at > now && valid_nonce(nonce) {
                    entries
                        .entry(nonce.to_owned())
                        .and_modify(|current| *current = (*current).max(expires_at))
                        .or_insert(expires_at);
                }
            }
        }
        let mut ledger = Self {
            path,
            entries,
            writes_since_compaction: 0,
        };
        ledger.compact()?;
        Ok(ledger)
    }

    /// Atomically consumes a live nonce, returning `false` when it was seen.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or expired input, or when the durable
    /// append cannot be written and synchronized.
    pub fn consume(&mut self, nonce: &str, expires_at: i64, now: i64) -> Result<bool, String> {
        if !valid_nonce(nonce) {
            return Err("nonce contains invalid characters".to_owned());
        }
        if expires_at <= now {
            return Err("cannot consume an expired nonce".to_owned());
        }
        self.entries.retain(|_, expiry| *expiry > now);
        if self.entries.contains_key(nonce) {
            return Ok(false);
        }

        let mut file = secure_append(&self.path)?;
        writeln!(file, "{expires_at}\t{nonce}").map_err(|error| error.to_string())?;
        file.sync_data().map_err(|error| error.to_string())?;
        self.entries.insert(nonce.to_owned(), expires_at);
        self.writes_since_compaction += 1;
        if self.writes_since_compaction >= COMPACT_EVERY {
            self.compact()?;
        }
        Ok(true)
    }

    fn compact(&mut self) -> Result<(), String> {
        let temporary = self.path.with_extension("tmp");
        let mut file = secure_truncate(&temporary)?;
        let mut entries = self.entries.iter().collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
        for (nonce, expires_at) in entries {
            writeln!(file, "{expires_at}\t{nonce}").map_err(|error| error.to_string())?;
        }
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temporary, &self.path).map_err(|error| error.to_string())?;
        sync_parent(&self.path)?;
        self.writes_since_compaction = 0;
        Ok(())
    }
}

fn valid_nonce(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len() <= 256
        && nonce.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'=' | b'+' | b'/')
        })
}

#[cfg(unix)]
fn secure_append(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())
}

#[cfg(unix)]
fn secure_truncate(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::ReplayLedger;
    use std::{fs, time::SystemTime};

    #[test]
    fn replay_remains_rejected_after_restart_and_expires() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("authority-replay-{unique}"));
        let path = directory.join("ledger");

        let mut ledger = ReplayLedger::open(&path, 100).expect("open");
        assert!(ledger.consume("abc_123", 200, 100).expect("consume"));
        assert!(!ledger.consume("abc_123", 200, 101).expect("replay"));
        drop(ledger);

        let mut reopened = ReplayLedger::open(&path, 102).expect("reopen");
        assert!(!reopened.consume("abc_123", 200, 102).expect("replay"));
        drop(reopened);

        let mut expired = ReplayLedger::open(&path, 200).expect("reopen expired");
        assert!(
            expired
                .consume("abc_123", 300, 200)
                .expect("reuse after expiry")
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }
}
