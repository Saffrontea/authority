//! Durable identity fences. Authentication happens before `advance`; kernel
//! cleanup happens afterwards and must be retried independently until successful.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use authority_contracts_model::fence::{GenerationBinding, RevocationSelector};
use serde::{Deserialize, Serialize};

const MAX_FENCES: usize = 8192;
const MAX_BYTES: u64 = 4 * 1024 * 1024;
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Identity {
    Subject { id: String },
    Device { id: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u8,
    domain: String,
    target: String,
    entries: Vec<(Identity, i64)>,
}

/// One store is exclusively owned by one actuator process and bound to one
/// domain/target. Its fences never expire. Sharing it without a process lock is
/// forbidden: two independent snapshots could otherwise roll each other back.
pub struct FenceStore {
    path: PathBuf,
    domain: String,
    target: String,
    entries: BTreeMap<Identity, i64>,
    poisoned: bool,
    _lock: File,
}

/// Immutable admission view; readers never wait for persistence or kernel work.
#[derive(Clone)]
pub struct FenceView {
    domain: String,
    entries: BTreeMap<Identity, i64>,
    poisoned: bool,
}
impl FenceView {
    #[must_use]
    pub fn rejects(&self, binding: &GenerationBinding) -> bool {
        rejects(&self.domain, &self.entries, self.poisoned, binding)
    }
}
fn rejects(
    domain: &str,
    entries: &BTreeMap<Identity, i64>,
    poisoned: bool,
    binding: &GenerationBinding,
) -> bool {
    poisoned
        || binding.validate().is_err()
        || binding.domain_id != domain
        || entries
            .get(&Identity::Subject {
                id: binding.subject_user_id.clone(),
            })
            .is_some_and(|minimum| binding.subject_generation < *minimum)
        || entries
            .get(&Identity::Device {
                id: binding.device_id.clone(),
            })
            .is_some_and(|minimum| binding.device_generation < *minimum)
}

impl FenceStore {
    /// # Errors
    /// Rejects malformed stores, cross-domain/target reuse, duplicate records and
    /// concurrent writers. Missing stores start empty; corrupt stores never do.
    pub fn open(path: impl Into<PathBuf>, domain: &str, target: &str) -> Result<Self, String> {
        let path = path.into();
        let check = GenerationBinding {
            domain_id: domain.into(),
            subject_user_id: target.into(),
            device_id: target.into(),
            subject_generation: 1,
            device_generation: 1,
        };
        check.validate().map_err(|e| e.to_string())?;
        let parent = parent(&path);
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let lock_path = path.with_file_name(format!(
            "{}.lock",
            path.file_name()
                .ok_or("missing fence filename")?
                .to_string_lossy()
        ));
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(lock_path)
            .map_err(|e| e.to_string())?;
        lock.try_lock()
            .map_err(|e| format!("fence store already locked: {e}"))?;
        let mut entries = BTreeMap::new();
        match File::open(&path) {
            Ok(file) => {
                let mut data = Vec::new();
                file.take(MAX_BYTES + 1)
                    .read_to_end(&mut data)
                    .map_err(|e| e.to_string())?;
                if data.len() as u64 > MAX_BYTES {
                    return Err("fence store exceeds size limit".into());
                }
                let snapshot: Snapshot =
                    serde_json::from_slice(&data).map_err(|e| e.to_string())?;
                if snapshot.version != 1
                    || snapshot.domain != domain
                    || snapshot.target != target
                    || snapshot.entries.len() > MAX_FENCES
                {
                    return Err("invalid fence store binding or capacity".into());
                }
                for (identity, generation) in snapshot.entries {
                    let selector = selector(&identity, generation);
                    selector.validate().map_err(|e| e.to_string())?;
                    if entries.insert(identity, generation).is_some() {
                        return Err("duplicate fence store identity".into());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        Ok(Self {
            path,
            domain: domain.into(),
            target: target.into(),
            entries,
            poisoned: false,
            _lock: lock,
        })
    }

    /// Call only after authenticating the notice and checking its domain, target,
    /// adapter and delivery window. Returns whether the durable fence advanced.
    /// A false return does NOT acknowledge kernel cleanup: retry cleanup anyway.
    ///
    /// # Errors
    /// Rejects decision selectors, invalid claims, exhausted capacity and I/O errors.
    /// After an ambiguous persistence failure this instance rejects every grant.
    pub fn advance(&mut self, scope: &RevocationSelector) -> Result<bool, String> {
        if self.poisoned {
            return Err("fence store requires recovery".into());
        }
        scope.validate().map_err(|e| e.to_string())?;
        let (identity, generation) = match scope {
            RevocationSelector::Subject {
                subject_user_id,
                minimum_generation,
            } => (
                Identity::Subject {
                    id: subject_user_id.clone(),
                },
                *minimum_generation,
            ),
            RevocationSelector::Device {
                device_id,
                minimum_generation,
            } => (
                Identity::Device {
                    id: device_id.clone(),
                },
                *minimum_generation,
            ),
            RevocationSelector::Decision { .. } => {
                return Err("decision revocation uses the decision ledger".into());
            }
        };
        if self
            .entries
            .get(&identity)
            .is_some_and(|old| *old >= generation)
        {
            return Ok(false);
        }
        if !self.entries.contains_key(&identity) && self.entries.len() >= MAX_FENCES {
            self.poisoned = true;
            return Err("identity fence capacity reached".into());
        }
        let mut next = self.entries.clone();
        next.insert(identity, generation);
        let data = serde_json::to_vec(&Snapshot {
            version: 1,
            domain: self.domain.clone(),
            target: self.target.clone(),
            entries: next.iter().map(|(id, g)| (id.clone(), *g)).collect(),
        })
        .map_err(|e| e.to_string())?;
        if let Err(error) = self.persist(&data) {
            self.poisoned = true;
            return Err(error);
        }
        self.entries = next;
        Ok(true)
    }

    /// Fail closed for malformed bindings, wrong domain and ambiguous I/O state.
    #[must_use]
    pub fn rejects(&self, binding: &GenerationBinding) -> bool {
        rejects(&self.domain, &self.entries, self.poisoned, binding)
    }

    #[must_use]
    pub fn view(&self) -> FenceView {
        FenceView {
            domain: self.domain.clone(),
            entries: self.entries.clone(),
            poisoned: self.poisoned,
        }
    }

    fn persist(&self, bytes: &[u8]) -> Result<(), String> {
        let temporary = self.path.with_file_name(format!(
            ".authority-fence-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        let result = (|| {
            file.write_all(bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            fs::rename(&temporary, &self.path).map_err(|e| e.to_string())?;
            File::open(parent(&self.path))
                .and_then(|directory| directory.sync_all())
                .map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn selector(identity: &Identity, minimum_generation: i64) -> RevocationSelector {
    match identity {
        Identity::Subject { id } => RevocationSelector::Subject {
            subject_user_id: id.clone(),
            minimum_generation,
        },
        Identity::Device { id } => RevocationSelector::Device {
            device_id: id.clone(),
            minimum_generation,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_capacity_cannot_leave_known_compromised_identity_admissible() {
        let directory = tempfile::tempdir().unwrap();
        let mut store =
            FenceStore::open(directory.path().join("fences"), "domain", "target").unwrap();
        store.entries = (0..MAX_FENCES)
            .map(|i| {
                (
                    Identity::Subject {
                        id: format!("subject-{i}"),
                    },
                    2,
                )
            })
            .collect();
        let fence = RevocationSelector::Subject {
            subject_user_id: "compromised".into(),
            minimum_generation: 2,
        };
        assert!(store.advance(&fence).is_err());
        let binding = GenerationBinding {
            domain_id: "domain".into(),
            subject_user_id: "compromised".into(),
            device_id: "device".into(),
            subject_generation: 1,
            device_generation: 1,
        };
        assert!(store.rejects(&binding));
    }
}
