use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceFilter, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-breadth")
}

#[test]
fn expands_mainstream_csharp_families_without_same_name_lookalikes() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let rule_counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(rule_counts["csharp-httpclient-outbound-http"], 3);
    assert_eq!(rule_counts["csharp-dapper-database-query"], 1);
    assert_eq!(
        rule_counts["csharp-jsonnet-instance-typename-deserialization"],
        1
    );
    assert_eq!(rule_counts["csharp-xmldocument-external-resolver"], 1);
    assert_eq!(rule_counts["csharp-xmldocument-null-resolver-control"], 1);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::OutboundNetworkRequest
                    | Capability::DatabaseQuery
                    | Capability::Deserialization
                    | Capability::XmlParsing
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 5);
    assert!(paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path == "positive/BreadthRisks.cs")
    }));
    assert!(!result.security_paths.iter().any(|path| {
        path.steps
            .iter()
            .any(|step| step.location.path == "control/BreadthControls.cs")
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "csharp-xmldocument-null-resolver-control"
            && item.kind == EvidenceKind::Validation
            && item.location.path == "control/BreadthControls.cs"
    }));
}

#[test]
fn exposes_unlinked_same_symbol_relationships_to_ai_investigation() {
    let funnel = mehscan_engine::investigation::relationship_funnel(&fixture_root())
        .expect("funnel should build")
        .results;
    assert_eq!(funnel.security_paths, 5);
    assert!(funnel.sinks_with_compatible_source_in_symbol > funnel.linked_sink_observations);
    assert!(funnel.unlinked_sinks_with_compatible_source_in_symbol >= 1);
    assert_eq!(
        funnel.by_capability[&Capability::OutboundNetworkRequest]
            .unlinked_sinks_with_compatible_source_in_symbol,
        1
    );

    let job = mehscan_engine::investigation::build_investigation_job(
        &fixture_root(),
        EvidenceFilter {
            capability: Some(Capability::HttpRequestData),
            ..EvidenceFilter::default()
        },
        Some(5),
        Some(25),
    )
    .expect("investigation job should build");
    assert!(job.units.iter().any(|unit| {
        unit.ai_guidance
            .iter()
            .any(|guidance| guidance.contains("did not connect"))
    }));
}
