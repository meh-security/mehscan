use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-redirect-flow")
}

#[test]
fn inventories_redirect_validation_and_builds_bounded_redirect_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    assert!(result.evidence.iter().any(|item| {
        item.capability == Capability::HttpRequestData
            && item.location.path == "positive/redirect-flow.ts"
            && item.enclosing_symbol.as_deref() == Some("guarded")
            && item
                .provenance
                .engine
                .ends_with("bounded-express-type-boundary")
    }));

    let parsers = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::UrlParsing)
        .collect::<Vec<_>>();
    assert_eq!(parsers.len(), 11);
    assert!(parsers.iter().all(|item| {
        item.kind == EvidenceKind::Sanitizer && item.location.path.starts_with("positive/")
    }));

    let validations = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::RedirectDestinationValidation)
        .collect::<Vec<_>>();
    assert_eq!(validations.len(), 7);
    assert!(validations.iter().all(|item| {
        item.kind == EvidenceKind::Validation && item.location.path.starts_with("positive/")
    }));

    let redirect_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::Redirect)
        .collect::<Vec<_>>();
    assert_eq!(redirect_paths.len(), 22);
    let states = redirect_paths
        .iter()
        .fold(BTreeMap::new(), |mut counts, path| {
            *counts.entry(path.state).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(states[&SecurityPathState::Direct], 7);
    assert_eq!(states[&SecurityPathState::Propagated], 7);
    assert_eq!(states[&SecurityPathState::Protected], 7);
    assert_eq!(states[&SecurityPathState::Unknown], 1);

    assert!(redirect_paths.iter().all(|path| {
        path.cwe_candidates == ["CWE-601"]
            && path
                .steps
                .first()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Source)
            && path
                .steps
                .last()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Sink)
            && path
                .steps
                .iter()
                .all(|step| !step.location.path.starts_with("negative/"))
    }));
    assert!(
        redirect_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .all(|path| {
                path.protection_evidence_ids.len() == 1
                    && path
                        .steps
                        .iter()
                        .any(|step| step.kind == SecurityPathStepKind::Protection)
            })
    );

    let guarded = redirect_paths
        .iter()
        .find(|path| path.state == SecurityPathState::Unknown)
        .expect("guarded lexical redirect should remain visible as unknown");
    assert!(
        guarded
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "control_flow_context_not_modeled")
    );
    assert!(guarded.steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::Assignment
            && step.symbol.as_deref() == Some("destination")
    }));
}
