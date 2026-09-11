use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, FixedOutputFormat, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-fixed-format-flow")
}

#[test]
fn fixed_hex_helpers_are_exact_sql_flow_barriers() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.schema_version, "2.1");
    assert_eq!(result.coverage.totals.scanned, 12);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let transforms = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::FixedFormatTransform)
        .collect::<Vec<_>>();
    assert_eq!(transforms.len(), 3);
    assert!(transforms.iter().all(|item| {
        item.kind == EvidenceKind::Sanitizer
            && item.location.path.starts_with("positive/routes/")
            && item.symbol_resolution.as_ref().is_some_and(|resolution| {
                resolution
                    .canonical
                    .contains("positive/lib/insecurity.hash")
            })
            && item
                .context
                .value_transform
                .as_ref()
                .is_some_and(|summary| {
                    summary.output_format == FixedOutputFormat::LowercaseHexadecimal
                        && matches!(summary.exact_length, 32 | 64 | 128)
                })
    }));

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::DatabaseQuery)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 12);
    assert!(
        paths
            .iter()
            .all(|path| path.state == SecurityPathState::Direct)
    );

    let paths_by_area = paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        let area = path.steps[0]
            .location
            .path
            .split('/')
            .next()
            .expect("fixture area");
        *counts.entry(area).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(paths_by_area["positive"], 3);
    assert_eq!(paths_by_area["negative"], 9);
    assert!(
        paths
            .iter()
            .filter(|path| { path.steps[0].location.path.starts_with("positive/") })
            .all(|path| {
                let source = result
                    .evidence
                    .iter()
                    .find(|item| item.id == path.source_evidence_id)
                    .expect("source evidence");
                source.location.start.column < 70
            })
    );
}
