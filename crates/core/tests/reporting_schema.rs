use std::collections::BTreeMap;

use mehscan_core::{
    CandidateReport, Capability, Confidence, Coverage, Evidence, EvidenceContext, EvidenceKind,
    Location, Position, Provenance, Resolution, SarifLog, ScanResult, SecurityPath,
    SecurityPathProvenance, SecurityPathState, SecurityPathStep, SecurityPathStepKind,
};

fn location(line: usize, start_column: usize, end_column: usize, start: usize) -> Location {
    Location {
        path: "query.py".to_string(),
        start: Position {
            line,
            column: start_column,
            byte_offset: start,
        },
        end: Position {
            line,
            column: end_column,
            byte_offset: start + end_column - start_column,
        },
    }
}

fn evidence(
    id: &str,
    kind: EvidenceKind,
    capability: Capability,
    location: Location,
    confidence: Confidence,
    rule_id: &str,
) -> Evidence {
    Evidence {
        id: id.to_string(),
        kind,
        capability,
        location,
        enclosing_symbol: Some("lookup".to_string()),
        captures: BTreeMap::new(),
        cwe_candidates: vec!["CWE-89".to_string()],
        tags: Vec::new(),
        confidence,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: "ast-grep 0.45.1".to_string(),
            rule_version: 1,
        },
        context: EvidenceContext::default(),
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    }
}

fn scan_result() -> ScanResult {
    let source_location = location(2, 13, 25, 28);
    let sink_location = location(3, 5, 26, 51);
    let source = evidence(
        "ev-source",
        EvidenceKind::Source,
        Capability::HttpRequestData,
        source_location.clone(),
        Confidence::Medium,
        "python-http-query-source",
    );
    let sink = evidence(
        "ev-sink",
        EvidenceKind::Sink,
        Capability::DatabaseQuery,
        sink_location.clone(),
        Confidence::High,
        "python-database-query",
    );
    ScanResult {
        schema_version: "1.8".to_string(),
        root: "C:/fixture".to_string(),
        evidence: vec![source, sink],
        security_paths: vec![SecurityPath {
            id: "path-0000000000000001".to_string(),
            source_evidence_id: "ev-source".to_string(),
            sink_evidence_id: "ev-sink".to_string(),
            capability: Capability::DatabaseQuery,
            cwe_candidates: vec!["CWE-89".to_string()],
            state: SecurityPathState::Direct,
            steps: vec![
                SecurityPathStep {
                    kind: SecurityPathStepKind::Source,
                    location: source_location,
                    evidence_id: Some("ev-source".to_string()),
                    symbol: None,
                },
                SecurityPathStep {
                    kind: SecurityPathStepKind::Sink,
                    location: sink_location,
                    evidence_id: Some("ev-sink".to_string()),
                    symbol: None,
                },
            ],
            protection_evidence_ids: Vec::new(),
            uncertainty_reasons: vec!["source_observation_not_high_confidence".to_string()],
            provenance: SecurityPathProvenance {
                engine: "mehscan bounded-local-flow 1".to_string(),
                maximum_propagation_depth: 4,
            },
        }],
        coverage: Coverage::default(),
        impact_scope: None,
        diagnostics: Vec::new(),
    }
}

#[test]
fn candidate_and_sarif_contracts_match_versioned_goldens() {
    let candidate = CandidateReport::from_scan(&scan_result()).expect("candidate report");
    let sarif = SarifLog::from_candidate_report(&candidate);
    let candidate_expected: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/expected/candidate-report-v1.0.json"
    )))
    .expect("candidate golden should parse");
    let sarif_expected: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/expected/sarif-v2.1.0.json"
    )))
    .expect("SARIF golden should parse");

    assert_eq!(
        serde_json::to_value(&candidate).expect("candidate should serialize"),
        candidate_expected
    );
    assert_eq!(
        serde_json::to_value(&sarif).expect("SARIF should serialize"),
        sarif_expected
    );
    let decoded_candidate: CandidateReport =
        serde_json::from_value(candidate_expected).expect("candidate should deserialize");
    let decoded_sarif: SarifLog =
        serde_json::from_value(sarif_expected).expect("SARIF should deserialize");
    assert_eq!(decoded_candidate, candidate);
    assert_eq!(decoded_sarif, sarif);
}
