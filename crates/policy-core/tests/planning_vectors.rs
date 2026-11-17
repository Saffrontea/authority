use std::{fs, path::Path};

use authority_policy_core::selection::PlanningEvidence;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    decision_id: String,
    planning: PlanningEvidence,
}

#[test]
fn planning_event_vectors_preserve_scope_and_executable_selection_evidence() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test-vectors/policy-plan-evaluated-v1");
    for (directory, expected) in [("valid", true), ("invalid", false)] {
        for entry in fs::read_dir(root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            let event = serde_json::from_slice::<Event>(&fs::read(&path).unwrap());
            let valid = event.is_ok_and(|event| {
                !event.decision_id.is_empty()
                    && event.decision_id.len() <= 128
                    && event.planning.is_consistent()
            });
            assert_eq!(valid, expected, "{}", path.display());
        }
    }
}
