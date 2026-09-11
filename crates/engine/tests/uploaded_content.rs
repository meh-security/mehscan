use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, Confidence, EvidenceKind, Language};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/uploaded-content")
}

#[test]
fn enumerates_uploaded_bytes_and_streams_across_priority_languages() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.schema_version, "2.1");
    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let evidence = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::UploadedFileContent)
        .collect::<Vec<_>>();
    assert_eq!(evidence.len(), 7);
    assert!(evidence.iter().all(|item| {
        item.kind == EvidenceKind::Source
            && item.confidence == Confidence::Medium
            && item.location.path.starts_with("positive/")
            && item.cwe_candidates == ["CWE-434"]
    }));

    let by_language = evidence.iter().fold(BTreeMap::new(), |mut counts, item| {
        let language = result
            .coverage
            .files
            .iter()
            .find(|file| file.path == item.location.path)
            .and_then(|file| file.language)
            .expect("evidence file language");
        *counts.entry(language).or_insert(0) += 1;
        counts
    });
    for language in [
        Language::Csharp,
        Language::Java,
        Language::Javascript,
        Language::Typescript,
        Language::Tsx,
        Language::Python,
        Language::Go,
    ] {
        assert_eq!(by_language.get(&language), Some(&1), "{language:?}");
    }
}
