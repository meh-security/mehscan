use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-duplicate-key-mutation")
}

#[test]
fn reports_only_first_checked_last_persisted_duplicate_key_mutation() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let custom = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("duplicate-key-object-mutation")
        })
        .collect::<Vec<_>>();
    assert_eq!(custom.len(), 2);
    assert!(
        custom
            .iter()
            .all(|item| item.location.path.starts_with("positive/"))
    );

    let source = custom
        .iter()
        .find(|item| item.kind == EvidenceKind::Source)
        .expect("typed raw body source");
    assert_eq!(source.capability, Capability::HttpRequestData);
    assert_eq!(source.captures["name"].text, "req.rawBody");

    let sink = custom
        .iter()
        .find(|item| item.kind == EvidenceKind::Sink)
        .expect("verified build/save mutation sink");
    assert_eq!(sink.capability, Capability::ResourceAccess);
    assert_eq!(sink.captures["duplicate_key"].text, "'BasketId'");
    assert_eq!(sink.captures["validated_value"].text, "basketIds[0]");
    assert_eq!(
        sink.captures["persisted_value"].text,
        "basketIds[basketIds.length - 1]"
    );
    assert_eq!(sink.related_evidence, [source.id.as_str()]);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::ResourceAccess)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].state, SecurityPathState::Unknown);
    assert_eq!(paths[0].source_evidence_id, source.id);
    assert_eq!(paths[0].sink_evidence_id, sink.id);
    assert!(paths[0].steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::Alias
            && step.symbol.as_deref() == Some("first duplicate-key value used by ownership check")
    }));
    assert!(paths[0].steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::Assignment
            && step.symbol.as_deref() == Some("last duplicate-key value persisted")
    }));
}
