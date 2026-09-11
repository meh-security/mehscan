use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c19")
}

#[test]
fn closes_dvcsharp_request_sql_privilege_hash_and_jwt_shapes() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(counts["csharp-ef-legacy-from-sql-query"], 1);
    assert_eq!(counts["csharp-request-controlled-role-assignment"], 1);
    assert_eq!(counts["csharp-role-assignment-caller-control"], 1);
    assert_eq!(counts["csharp-password-fast-hash"], 1);
    assert_eq!(counts["csharp-predictable-password-reset-hash"], 1);
    assert_eq!(counts["csharp-hardcoded-jwt-signing-key"], 1);
    assert_eq!(counts["csharp-jwt-signing-with-hardcoded-key"], 1);

    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "csharp-http-request-data"
            && item.location.path == "DvcsharpShapes.cs"
            && item.captures["name"].text == "\"url\""
    }));
    assert!(!result.evidence.iter().any(|item| {
        item.rule_id == "csharp-password-fast-hash" && item.captures["password"].text == "contents"
    }));

    for capability in [
        Capability::DatabaseQuery,
        Capability::OutboundNetworkRequest,
        Capability::ResourceAccess,
        Capability::TokenGeneration,
    ] {
        assert!(
            result
                .security_paths
                .iter()
                .any(|path| path.capability == capability)
        );
    }
    let privilege = result
        .security_paths
        .iter()
        .find(|path| {
            result.evidence.iter().any(|item| {
                item.id == path.sink_evidence_id
                    && item.rule_id == "csharp-request-controlled-role-assignment"
            })
        })
        .expect("persisted role assignment should produce a bounded path");
    assert!(privilege.steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::Assignment
            && step.symbol.as_deref()
                == Some("request-bound privilege value assigned to a persisted identity property")
    }));
    assert!(result.evidence.iter().any(|item| {
        item.kind == EvidenceKind::Guard && item.rule_id == "csharp-role-assignment-caller-control"
    }));

    let reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), true)
            .expect("fixture review material should build");
    let jwt = reviews
        .reviews
        .iter()
        .find(|review| review.candidate.source.rule_id == "csharp-hardcoded-jwt-signing-key")
        .expect("hardcoded JWT path should be reviewable");
    let definition = jwt
        .facts
        .iter()
        .find(|fact| fact.role == "captured_definition_context")
        .expect("captured key definition should be supplied to review");
    assert_eq!(definition.symbol, "TokenSecret");
    assert!(definition.excerpt.contains("TokenSecret"));
    assert!(definition.excerpt.contains("<redacted>"));
    assert!(!definition.excerpt.contains("fixture-signing-secret-value"));
    assert!(jwt.open_questions.iter().any(|question| {
        question.contains("signing-key material") && question.contains("secret provider")
    }));
}
