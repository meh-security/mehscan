use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c16")
}

#[test]
fn relates_exact_zip_entry_paths_to_writes_and_only_exact_containment() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let sources = result
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Source && item.capability == Capability::ArchiveEntryPath
        })
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 11);
    assert!(
        sources
            .iter()
            .all(|item| item.rule_id == "csharp-zip-entry-full-name")
    );

    let protections = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-zip-entry-rooted-containment")
        .collect::<Vec<_>>();
    assert_eq!(protections.len(), 2);

    let archive_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            sources
                .iter()
                .any(|source| source.id == path.source_evidence_id)
                && path.capability == Capability::FilesystemWrite
        })
        .collect::<Vec<_>>();
    assert_eq!(archive_paths.len(), 10);
    assert_eq!(
        archive_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        2
    );
    assert!(
        archive_paths
            .iter()
            .all(|path| path.cwe_candidates == ["CWE-22"])
    );
    assert!(!result.evidence.iter().any(|item| {
        item.enclosing_symbol
            .as_deref()
            .is_some_and(|symbol| symbol.contains("Shadow"))
            && matches!(
                item.rule_id.as_str(),
                "csharp-zip-entry-full-name" | "csharp-zip-entry-extract-to-file"
            )
    }));
}
