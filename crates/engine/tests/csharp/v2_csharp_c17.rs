use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c17")
}

#[test]
fn relates_exact_streamed_request_content_to_file_backed_storage() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let rules = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            if item.provenance.engine == "mehscan bounded-csharp-streaming-upload 1" {
                *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            }
            counts
        });
    assert_eq!(rules["csharp-http-request-body-stream"], 6);
    assert_eq!(rules["csharp-multipart-section-body"], 5);
    assert_eq!(rules["csharp-streamed-upload-file-copy"], 5);
    assert_eq!(rules["csharp-multipart-content-disposition-filename"], 1);
    assert_eq!(rules["csharp-multipart-reader-limit"], 2);
    assert_eq!(rules["csharp-request-upload-size-limit"], 2);

    let storage_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::FileUpload)
        .collect::<Vec<_>>();
    assert_eq!(storage_paths.len(), 5);
    assert!(
        storage_paths
            .iter()
            .all(|path| path.cwe_candidates == ["CWE-434"]
                && path.state == SecurityPathState::Direct
                && path.protection_evidence_ids.is_empty())
    );
    assert!(!result.evidence.iter().any(|item| {
        item.location.path == "Lookalikes.cs"
            && matches!(item.kind, EvidenceKind::Source | EvidenceKind::Sink)
            && matches!(
                item.capability,
                Capability::UploadedFileContent | Capability::FileUpload
            )
    }));
}
