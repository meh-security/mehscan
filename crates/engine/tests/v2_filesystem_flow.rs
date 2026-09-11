use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-filesystem-flow")
}

#[test]
fn inventories_path_protections_and_builds_bounded_filesystem_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let canonicalizations = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::PathCanonicalization)
        .collect::<Vec<_>>();
    // The C# and Java containment expressions each canonicalize both operands.
    assert_eq!(canonicalizations.len(), 12);
    assert!(canonicalizations.iter().all(|item| {
        item.kind == EvidenceKind::Sanitizer && item.location.path.starts_with("positive/")
    }));

    let containment_checks = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::PathContainmentCheck)
        .collect::<Vec<_>>();
    assert_eq!(containment_checks.len(), 7);
    assert!(containment_checks.iter().all(|item| {
        item.kind == EvidenceKind::Validation && item.location.path.starts_with("positive/")
    }));

    let filesystem_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::FilesystemRead | Capability::FilesystemWrite
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(filesystem_paths.len(), 22);
    let states = filesystem_paths
        .iter()
        .fold(BTreeMap::new(), |mut counts, path| {
            *counts.entry(path.state).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(states[&SecurityPathState::Direct], 7);
    assert_eq!(states[&SecurityPathState::Propagated], 7);
    assert_eq!(states[&SecurityPathState::Protected], 7);
    assert_eq!(states[&SecurityPathState::Unknown], 1);

    assert!(filesystem_paths.iter().all(|path| {
        path.cwe_candidates == ["CWE-22"]
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
        filesystem_paths
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

    let layout_sinks = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("express-pug-layout-options")
        })
        .collect::<Vec<_>>();
    assert_eq!(layout_sinks.len(), 2);
    assert!(layout_sinks.iter().all(|sink| {
        sink.kind == EvidenceKind::Sink
            && sink.capability == Capability::FilesystemRead
            && sink.confidence == mehscan_core::Confidence::Medium
            && sink.cwe_candidates == ["CWE-22"]
            && sink.related_evidence.len() == 1
    }));

    let layout_path = filesystem_paths
        .iter()
        .find(|path| path.state == SecurityPathState::Unknown)
        .expect("the reachable request-body layout spread should remain an unknown path");
    assert_eq!(layout_path.steps.len(), 3);
    assert!(
        layout_path
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "control_flow_context_not_modeled")
    );
    assert!(layout_path.steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::Alias
            && step.symbol.as_deref() == Some("req.body spread into render layout options")
    }));
    assert!(
        layout_path
            .steps
            .iter()
            .all(|step| step.location.path == "positive/filesystem-flow.ts")
    );
}
