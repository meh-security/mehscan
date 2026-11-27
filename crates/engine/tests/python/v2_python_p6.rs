use std::path::PathBuf;

use mehscan_core::{EvidenceKind, HttpRouteAccess, ResourcePolicyState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p6")
}

#[test]
fn models_flask_routes_session_trust_templates_and_sqlalchemy_policy() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let handlers = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-flask-handler-entrypoint")
        .collect::<Vec<_>>();
    assert_eq!(handlers.len(), 3);
    assert!(handlers.iter().any(|item| {
        item.context.http_routes.iter().any(|route| {
            route.path == "/items/<int:item_id>" && route.access == HttpRouteAccess::Unknown
        })
    }));
    assert!(
        handlers
            .iter()
            .any(|item| item.context.http_routes.iter().any(|route| {
                route.path == "/items/protected/<int:item_id>"
                    && route.method == "POST"
                    && route.access == HttpRouteAccess::Authenticated
            }))
    );

    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.rule_id == "python-flask-unsigned-client-session")
    );
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "python-flask-authenticated-session-control"
            && item.kind == EvidenceKind::Validation
    }));
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.rule_id == "python-flask-session-cookie-flags-review")
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.rule_id == "python-flask-session-cookie-control")
    );

    let sqlalchemy = result
        .evidence
        .iter()
        .filter(|item| item.rule_id.starts_with("python-sqlalchemy-"))
        .collect::<Vec<_>>();
    assert_eq!(sqlalchemy.len(), 2);
    assert_eq!(
        sqlalchemy
            .iter()
            .filter(|item| item.kind == EvidenceKind::Sink)
            .count(),
        1
    );
    assert!(sqlalchemy.iter().any(|item| {
        item.context
            .resource_policy
            .as_ref()
            .is_some_and(|policy| policy.state == ResourcePolicyState::OwnerScoped)
    }));
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.rule_id == "python-flask-template-unsafe-output")
    );
}
