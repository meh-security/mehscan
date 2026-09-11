use std::path::PathBuf;

use mehscan_core::{Capability, HttpRouteAccess};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-go-g1")
}

#[test]
fn adds_go_request_route_identity_and_mongo_context_without_json_cwe_502() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert!(
        !result
            .evidence
            .iter()
            .any(|item| item.rule_id == "go-gob-deserialization")
    );

    for rule in [
        "go-net-http-request-body",
        "go-gorilla-mux-route-variables",
        "go-query-string-credential",
        "go-jwt-parse-unverified-review",
        "go-request-object-mongodb-filter",
        "go-mongodb-query",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }
    let handler_facts = result
        .evidence
        .iter()
        .filter(|item| item.enclosing_symbol.as_deref() == Some("Handle"))
        .collect::<Vec<_>>();
    assert!(!handler_facts.is_empty());
    assert!(handler_facts.iter().all(|item| {
        item.context.http_routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/items/{id}"
                && route.access == HttpRouteAccess::Authenticated
        })
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "go-mongodb-query" && item.capability == Capability::DatabaseQuery
    }));
}
