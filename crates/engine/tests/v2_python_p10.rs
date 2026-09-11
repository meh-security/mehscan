use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p10")
}

#[test]
fn relates_request_content_only_to_proved_python_source_file_writes() {
    let first = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let second = mehscan_engine::scan_path(fixture_root()).expect("repeat scan should succeed");

    assert_eq!(first.coverage.totals.scanned, 2);
    assert_eq!(first.coverage.totals.parse_failed, 0);
    let writes = first
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-source-file-content-write")
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 3);
    assert!(writes.iter().all(|item| {
        item.kind == EvidenceKind::Sink
            && item.capability == Capability::FilesystemWrite
            && item.captures.contains_key("content")
            && item.captures.contains_key("path")
            && item.cwe_candidates == ["CWE-94"]
    }));
    assert_eq!(
        writes
            .iter()
            .map(|item| item.location.start.line)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([8, 14, 37])
    );

    let paths = first
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::FilesystemWrite
                && path.cwe_candidates.iter().any(|cwe| cwe == "CWE-94")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2);
    assert!(
        paths
            .iter()
            .all(|path| path.state != SecurityPathState::Protected)
    );
    assert_eq!(
        paths
            .iter()
            .filter_map(|path| path.steps.last())
            .map(|step| step.location.start.line)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([8, 14])
    );
    assert_eq!(first.evidence, second.evidence);
    assert_eq!(first.security_paths, second.security_paths);

    let review_job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), None, false)
            .expect("review job should build");
    let source_write_reviews = review_job
        .reviews
        .iter()
        .filter(|review| review.candidate.sink.rule_id == "python-source-file-content-write")
        .collect::<Vec<_>>();
    assert_eq!(source_write_reviews.len(), 2);
    assert!(source_write_reviews.iter().all(|review| {
        review
            .facts
            .iter()
            .any(|fact| fact.role == "python_source_file_consumer_context")
            && review.decision_facts.unresolved.is_empty()
            && review.open_questions == [
                "Does an exact Python import or loader reference the request-overwritten source file, allowing its contents to execute on application startup, reload, or worker restart?"
            ]
    }));
}
