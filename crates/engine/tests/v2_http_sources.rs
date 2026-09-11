use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, Confidence, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-http-sources")
}

#[test]
fn inventories_request_data_across_priority_languages() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let sources: Vec<_> = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::HttpRequestData)
        .collect();
    assert_eq!(sources.len(), 35);
    assert!(sources.iter().all(|item| item.kind == EvidenceKind::Source));
    assert!(
        sources
            .iter()
            .all(|item| item.confidence == Confidence::Medium)
    );
    assert!(
        sources
            .iter()
            .all(|item| item.location.path.starts_with("positive/"))
    );

    let by_language = sources.iter().fold(BTreeMap::new(), |mut counts, item| {
        let extension = item.location.path.rsplit('.').next().unwrap_or_default();
        *counts.entry(extension.to_string()).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(by_language["cs"], 5);
    assert_eq!(by_language["java"], 5);
    assert_eq!(by_language["js"], 5);
    assert_eq!(by_language["ts"], 5);
    assert_eq!(by_language["tsx"], 5);
    assert_eq!(by_language["py"], 5);
    assert_eq!(by_language["go"], 5);
}

#[test]
fn recognizes_nested_sequelize_receiver_without_claiming_flow() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let sinks: Vec<_> = result
        .evidence
        .iter()
        .filter(|item| item.rule_id.ends_with("database-query"))
        .collect();

    assert_eq!(sinks.len(), 3);
    assert!(sinks.iter().all(|item| item.kind == EvidenceKind::Sink));
    assert!(
        sinks
            .iter()
            .all(|item| item.captures["database"].text == "models")
    );
    assert!(sinks.iter().all(|item| item.related_evidence.is_empty()));
}
