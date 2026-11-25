use authority_contracts_model::fence::{GenerationBinding, RevocationSelector};
use authority_replay_ledger::fence::FenceStore;
use std::os::unix::fs::PermissionsExt;

fn binding(
    subject: &str,
    device: &str,
    subject_generation: i64,
    device_generation: i64,
) -> GenerationBinding {
    GenerationBinding {
        domain_id: "domain".into(),
        subject_user_id: subject.into(),
        device_id: device.into(),
        subject_generation,
        device_generation,
    }
}

#[test]
fn subject_and_device_fences_survive_restart_and_never_roll_back() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fences");
    let mut store = FenceStore::open(&path, "domain", "target").unwrap();
    let subject = RevocationSelector::Subject {
        subject_user_id: "alice".into(),
        minimum_generation: 3,
    };
    let device = RevocationSelector::Device {
        device_id: "compromised".into(),
        minimum_generation: 5,
    };
    assert!(store.advance(&subject).unwrap());
    assert!(store.advance(&device).unwrap());
    assert!(
        !store
            .advance(&RevocationSelector::Subject {
                subject_user_id: "alice".into(),
                minimum_generation: 2
            })
            .unwrap()
    );
    assert!(store.rejects(&binding("alice", "clean", 2, 1)));
    assert!(store.rejects(&binding("bob", "compromised", 1, 4)));
    assert!(!store.rejects(&binding("alice", "clean", 3, 1)));
    assert!(!store.rejects(&binding("bob", "clean", 1, 1)));
    assert!(FenceStore::open(&path, "domain", "target").is_err());
    drop(store);
    let mut restarted = FenceStore::open(&path, "domain", "target").unwrap();
    assert!(restarted.rejects(&binding("alice", "clean", 2, 1)));
    assert!(restarted.rejects(&binding("bob", "compromised", 1, 4)));
    assert!(!restarted.advance(&subject).unwrap());
    assert!(restarted.rejects(&binding("alice", "clean", 0, 1)));
    let mut wrong_domain = binding("bob", "clean", 1, 1);
    wrong_domain.domain_id = "other".into();
    assert!(restarted.rejects(&wrong_domain));
    drop(restarted);
    assert!(FenceStore::open(&path, "other", "target").is_err());
    assert!(FenceStore::open(&path, "domain", "other").is_err());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn corruption_and_failed_commit_never_reopen_access() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fences");
    std::fs::write(&path, b"truncated").unwrap();
    assert!(FenceStore::open(&path, "domain", "target").is_err());
    std::fs::remove_file(&path).unwrap();
    let mut store = FenceStore::open(&path, "domain", "target").unwrap();
    // Force rename failure after writing/fsyncing the temporary snapshot.
    std::fs::create_dir(&path).unwrap();
    let fence = RevocationSelector::Subject {
        subject_user_id: "alice".into(),
        minimum_generation: 2,
    };
    assert!(store.advance(&fence).is_err());
    assert!(store.rejects(&binding("alice", "clean", 1, 1)));
    assert!(store.rejects(&binding("bob", "clean", 1, 1)));
    assert!(store.advance(&fence).is_err());
    drop(store);
    assert!(FenceStore::open(&path, "domain", "target").is_err());
}
