use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, Confidence, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-sql-protection")
}

#[test]
fn inventories_sql_parameterization_without_suppressing_sinks() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let protections: Vec<_> = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::SqlParameterization)
        .collect();
    assert_eq!(protections.len(), 8);
    assert!(
        protections
            .iter()
            .all(|item| item.kind == EvidenceKind::Sanitizer)
    );
    assert!(
        protections
            .iter()
            .all(|item| item.confidence == Confidence::Medium)
    );
    assert!(
        protections
            .iter()
            .all(|item| item.location.path.starts_with("positive/"))
    );

    let by_extension = protections
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            let extension = item.location.path.rsplit('.').next().unwrap_or_default();
            *counts.entry(extension.to_string()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(by_extension["cs"], 1);
    assert_eq!(by_extension["java"], 2);
    assert_eq!(by_extension["js"], 1);
    assert_eq!(by_extension["ts"], 1);
    assert_eq!(by_extension["tsx"], 1);
    assert_eq!(by_extension["py"], 1);
    assert_eq!(by_extension["go"], 1);

    let sinks = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::DatabaseQuery)
        .count();
    assert_eq!(sinks, 14);
    assert!(
        result
            .evidence
            .iter()
            .all(|item| item.related_evidence.is_empty())
    );
}
