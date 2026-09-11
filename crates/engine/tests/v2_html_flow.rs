use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-html-flow")
}

#[test]
fn inventories_html_encoding_and_builds_contextual_bounded_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 16);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let protections = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::HtmlEncoding)
        .collect::<Vec<_>>();
    assert_eq!(protections.len(), 8);
    assert!(
        protections
            .iter()
            .all(|item| item.kind == EvidenceKind::Sanitizer)
    );
    assert_eq!(
        protections
            .iter()
            .filter(|item| item.location.path.starts_with("positive/"))
            .count(),
        7
    );

    let html_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::HtmlOutput)
        .collect::<Vec<_>>();
    assert_eq!(html_paths.len(), 23);
    let states = html_paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        *counts.entry(path.state).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(states[&SecurityPathState::Direct], 8);
    assert_eq!(states[&SecurityPathState::Propagated], 7);
    assert_eq!(states[&SecurityPathState::Protected], 7);
    assert_eq!(states[&SecurityPathState::Unknown], 1);

    assert!(html_paths.iter().all(|path| {
        path.cwe_candidates == ["CWE-79"]
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
        html_paths
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

    let ignored = html_paths
        .iter()
        .find(|path| {
            path.steps
                .last()
                .is_some_and(|step| step.location.path == "mixed/ignored-protection.js")
        })
        .expect("unencoded sibling value should retain a path");
    assert_eq!(ignored.state, SecurityPathState::Direct);
    assert!(ignored.protection_evidence_ids.is_empty());

    assert!(result.evidence.iter().any(|item| {
        item.location.path == "negative/conservative.js"
            && item.capability == Capability::HttpRequestData
    }));
    assert!(result.evidence.iter().any(|item| {
        item.location.path == "negative/conservative.js"
            && item.capability == Capability::HtmlOutput
    }));

    let subtitle_sources = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("local-subtitle-file-source")
        })
        .collect::<Vec<_>>();
    assert_eq!(subtitle_sources.len(), 2);
    assert!(subtitle_sources.iter().all(|source| {
        source.kind == EvidenceKind::Source
            && source.capability == Capability::StoredUserContent
            && source.related_evidence.len() == 1
    }));

    let subtitle_path = html_paths
        .iter()
        .find(|path| path.state == SecurityPathState::Unknown)
        .expect("the stored subtitle insertion should remain an unknown path");
    assert_eq!(subtitle_path.steps.len(), 4);
    assert!(
        subtitle_path
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "stored_file_origin_is_syntactic")
    );
    assert!(
        subtitle_path
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "stored_file_to_html_flow_is_syntactic")
    );
    assert!(subtitle_path.steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::Alias
            && step.symbol.as_deref() == Some("compiledTemplate via subtitle script replacement")
    }));
}
