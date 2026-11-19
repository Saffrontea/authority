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
        .join("../../contracts/test-vectors/policy-plan-evaluated-v2");
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

#[test]
fn planning_accepts_only_the_current_explicit_format() {
    let event: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/test-vectors/policy-plan-evaluated-v2/valid/existing-route.json"
    ))
    .unwrap();
    for version in [0, 1, 3, 255] {
        let mut value = event["planning"].clone();
        value["version"] = serde_json::json!(version);
        let evidence: PlanningEvidence = serde_json::from_value(value).unwrap();
        assert!(!evidence.is_consistent());
    }
    for field in ["environment", "derivations"] {
        let mut value = event["planning"].clone();
        let object = if field == "environment" {
            "resources"
        } else {
            "plan"
        };
        value[object].as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<PlanningEvidence>(value).is_err());
    }
}
