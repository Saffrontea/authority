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

#[test]
fn observation_lease_bounds_every_candidate_and_matches_the_recorded_environment() {
    use authority_contracts_model::observation::SignedEndpointObservationV1;
    let event: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/test-vectors/policy-plan-evaluated-v2/valid/existing-route.json"
    ))
    .unwrap();
    let mut planning = event["planning"].clone();
    let clock = planning["evaluated_at"].as_i64().unwrap();
    let mut report: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/test-vectors/endpoint-observation-v1/valid/basic.json"
    ))
    .unwrap();
    report["observation"]["challenge"]["domain_id"] = planning["binding"]["domain_id"].clone();
    report["observation"]["challenge"]["target_node_id"] =
        planning["binding"]["target_node_id"].clone();
    report["observation"]["facts"] = planning["resources"]["environment"].clone();
    report["observation"]["observed_at"] = clock.into();
    report["observation"]["expires_at"] = (clock + 600).into();
    report["observation"]["challenge"]["issued_at"] = clock.into();
    report["observation"]["challenge"]["expires_at"] = (clock + 30).into();
    planning["resources"]["observation"] = report.clone();
    assert!(
        serde_json::from_value::<PlanningEvidence>(planning.clone())
            .unwrap()
            .is_consistent()
    );

    // The report itself is still active and structurally valid, but cannot
    // support the twenty-second admission or its longer-lived alternative.
    report["observation"]["observed_at"] = (clock - 590).into();
    report["observation"]["expires_at"] = (clock + 10).into();
    report["observation"]["challenge"]["issued_at"] = (clock - 590).into();
    report["observation"]["challenge"]["expires_at"] = (clock - 560).into();
    let active: SignedEndpointObservationV1 = serde_json::from_value(report.clone()).unwrap();
    assert!(active.observation.active(clock));
    planning["resources"]["observation"] = report;
    assert!(
        !serde_json::from_value::<PlanningEvidence>(planning)
            .unwrap()
            .is_consistent()
    );
}
