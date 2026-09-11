use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p3b")
}

#[test]
fn covers_python_command_eval_deserialization_xxe_and_csrf_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let path_capabilities = result
        .security_paths
        .iter()
        .map(|path| path.capability)
        .collect::<BTreeSet<_>>();
    assert!(path_capabilities.contains(&Capability::ProcessExecution));
    assert!(path_capabilities.contains(&Capability::DynamicCodeExecution));
    assert!(path_capabilities.contains(&Capability::Deserialization));
    assert!(path_capabilities.contains(&Capability::XmlParsing));
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::ProcessExecution
            && path.state == SecurityPathState::Protected
            && path
                .steps
                .first()
                .is_some_and(|step| step.location.path == "safe.py")
    }));

    let csrf = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "python-django-csrf-exempt-handler")
        .expect("decorated routed handler should retain CSRF context");
    assert_eq!(csrf.kind, EvidenceKind::SecurityConfiguration);
    assert_eq!(csrf.cwe_candidates, ["CWE-352"]);
    assert!(
        csrf.context
            .http_routes
            .iter()
            .any(|route| route.path == "/command")
    );

    assert!(result.evidence.iter().any(|item| {
        item.location.path == "safe.py"
            && item.capability == Capability::ProcessArgumentSeparation
            && item.kind == EvidenceKind::Sanitizer
    }));
    assert!(result.evidence.iter().any(|item| {
        item.location.path == "safe.py"
            && item.capability == Capability::DeserializationRestriction
            && item.kind == EvidenceKind::Validation
    }));
    assert!(!result.evidence.iter().any(|item| {
        item.location.path == "safe.py" && item.rule_id == "python-pickle-deserialization"
    }));
}
