use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-dynamic-response-field")
}

#[test]
fn reports_only_request_selected_sensitive_fields_that_reach_a_response() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let custom = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("dynamic-sensitive-response-field")
        })
        .collect::<Vec<_>>();
    assert_eq!(custom.len(), 4);
    assert!(
        custom
            .iter()
            .all(|item| item.location.path.starts_with("positive/"))
    );

    let source = custom
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Source && item.location.path == "positive/dynamic-fields.ts"
        })
        .expect("optional Express query source");
    assert_eq!(source.capability, Capability::HttpRequestData);
    assert_eq!(source.captures["name"].text, "req.query?.fields");

    let sink = custom
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Sink && item.location.path == "positive/dynamic-fields.ts"
        })
        .expect("dynamic sensitive response-field sink");
    assert_eq!(sink.capability, Capability::ResourceAccess);
    assert_eq!(sink.cwe_candidates, ["CWE-200"]);
    assert_eq!(sink.captures["field_selector"].text, "field");
    assert_eq!(sink.captures["selected_value"].text, "user?.data[field]");
    assert_eq!(sink.captures["response"].text, "res.json(response)");
    assert_eq!(sink.related_evidence, [source.id.as_str()]);
    assert!(
        sink.tags
            .iter()
            .any(|tag| tag == "sensitive-fields:password,totpSecret")
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-200"])
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2);
    assert!(
        paths
            .iter()
            .all(|path| path.capability == Capability::ResourceAccess)
    );
    assert!(
        paths
            .iter()
            .all(|path| path.state == SecurityPathState::Unknown)
    );
    let direct_case = paths
        .iter()
        .find(|path| path.sink_evidence_id == sink.id)
        .expect("unfiltered dynamic response-field path");
    assert_eq!(direct_case.source_evidence_id, source.id);
    assert!(
        direct_case
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "dynamic_response_field_exposure_is_syntactic")
    );
    assert!(direct_case.steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::Alias
            && step.symbol.as_deref() == Some("response object reaches Express JSON output")
    }));
    assert!(paths.iter().any(|path| {
        result
            .evidence
            .iter()
            .find(|item| item.id == path.sink_evidence_id)
            .is_some_and(|item| item.location.path == "positive/sensitive-allowlist.ts")
    }));
}
