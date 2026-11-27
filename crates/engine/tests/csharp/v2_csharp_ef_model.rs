use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, ResourcePolicyState, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-ef-model")
}

#[test]
fn models_ef_where_key_scope_mass_assignment_and_sensitive_output() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let observations = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine == "mehscan csharp-ef-model-policy 1")
        .collect::<Vec<_>>();
    let counts = observations
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(counts["csharp-ef-unscoped-resource-query"], 5);
    assert_eq!(counts["csharp-ef-sensitive-model-mass-assignment"], 2);
    assert_eq!(
        counts["csharp-request-selected-sensitive-response-field"],
        1
    );
    assert_eq!(counts["csharp-ef-owner-scoped-query-control"], 1);
    assert_eq!(counts["csharp-ef-explicit-field-update-control"], 1);
    assert_eq!(counts["csharp-sensitive-field-allowlist-control"], 1);

    let owner_control = observations
        .iter()
        .find(|item| item.rule_id == "csharp-ef-owner-scoped-query-control")
        .expect("owner-scoped Where control");
    assert_eq!(owner_control.kind, EvidenceKind::Validation);
    assert_eq!(
        owner_control
            .context
            .resource_policy
            .as_ref()
            .map(|policy| policy.state),
        Some(ResourcePolicyState::OwnerScoped)
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::ResourceAccess)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 8);
    assert!(paths.iter().all(|path| {
        path.state == SecurityPathState::Propagated
            && path
                .steps
                .iter()
                .all(|step| step.location.path == "positive/EfRisks.cs")
    }));
    let cwes = paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        *counts
            .entry(path.cwe_candidates.as_slice())
            .or_insert(0usize) += 1;
        counts
    });
    assert_eq!(cwes[&["CWE-639".to_string()][..]], 5);
    assert_eq!(cwes[&["CWE-915".to_string()][..]], 2);
    assert_eq!(cwes[&["CWE-200".to_string()][..]], 1);
    assert!(!result.security_paths.iter().any(|path| {
        path.steps
            .iter()
            .any(|step| step.location.path == "control/ScopedAndMapped.cs")
    }));
}
