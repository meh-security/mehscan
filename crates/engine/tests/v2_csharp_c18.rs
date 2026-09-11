use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c18")
}

#[test]
fn relates_request_owned_authorization_to_identity_role_assignment() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let privilege = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine == "mehscan csharp bounded privilege assignment 1")
        .collect::<Vec<_>>();
    assert_eq!(privilege.len(), 3);
    let sink = privilege
        .iter()
        .find(|item| item.rule_id == "csharp-request-controlled-role-assignment")
        .expect("request-owned role assignment should remain a candidate sink");
    assert_eq!(sink.location.path, "Vulnerable.cs");
    assert_eq!(sink.kind, EvidenceKind::Sink);
    assert_eq!(sink.capability, Capability::ResourceAccess);
    assert_eq!(sink.captures["assigned_fields"].text, "model.MakeAdmin");
    assert_eq!(
        sink.captures["client_authorization_guard"].text,
        "!model.IsIssuerAdmin"
    );
    assert_eq!(sink.captures["role"].text, "\"admin\"");

    let controls = privilege
        .iter()
        .filter(|item| item.rule_id == "csharp-role-assignment-caller-control")
        .collect::<Vec<_>>();
    assert_eq!(controls.len(), 2);
    assert!(controls.iter().all(|item| {
        item.location.path == "Controls.cs"
            && item.kind == EvidenceKind::Guard
            && item
                .tags
                .iter()
                .any(|tag| tag == "server-owned-caller-authorization")
    }));
    assert!(
        privilege
            .iter()
            .all(|item| item.location.path != "Lookalikes.cs")
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.sink_evidence_id == sink.id)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].state, SecurityPathState::Unknown);
    assert_eq!(paths[0].cwe_candidates, ["CWE-915"]);
    assert!(paths[0].steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::IneffectiveProtection
            && step.symbol.as_deref()
                == Some("request-bound model property cannot establish caller privilege")
    }));
    assert!(paths[0].steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::Alias
            && step.symbol.as_deref()
                == Some("request-bound decision controls administrative role assignment")
    }));
}
