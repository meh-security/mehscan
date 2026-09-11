use std::path::PathBuf;

use mehscan_core::{Capability, HttpRouteAccess};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-go-g2-breadth")
}

#[test]
fn adds_httprouter_sql_helper_and_cookie_policy_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert_eq!(result.security_paths.len(), 3);
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.cwe_candidates == ["CWE-639"])
            .count(),
        2
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.rule_id == "go-cookie-helper-source")
    );

    let unsafe_query = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "go-sql-parameter-query-summary")
        .expect("unsafe helper should become a caller-side sink");
    assert_eq!(unsafe_query.capability, Capability::DatabaseQuery);
    assert!(unsafe_query.context.http_routes.iter().any(|route| {
        route.method == "GET"
            && route.path == "/unsafe"
            && route.access == HttpRouteAccess::Authenticated
    }));

    let safe = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "go-sql-parameterization-summary-control")
        .expect("prepared helper should remain a caller-side control");
    assert_eq!(safe.capability, Capability::SqlParameterization);
    assert!(
        safe.context
            .http_routes
            .iter()
            .any(|route| route.path == "/safe")
    );

    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "go-cookie-security-policy-review")
            .count(),
        2
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "go-cookie-security-policy-control")
            .count(),
        1
    );

    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("Go SQL reviews should build");
    let parameterized = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "go-dynamic-sql-prepare")
        })
        .expect("parameterized SQL observation");
    assert!(parameterized.decision_facts.unresolved.is_empty());
    assert_eq!(parameterized.decision_facts.effective_controls.len(), 1);
}
