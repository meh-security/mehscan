use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-next-app-router")
}

#[test]
fn models_next_app_router_boundaries_postgres_js_and_production_test_routes() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert!(result.coverage.files.iter().any(|file| {
        file.path == "src/app/api/webhooks/test/route.ts"
            && file.status == mehscan_core::FileStatus::Scanned
    }));
    assert!(result.coverage.files.iter().any(|file| {
        file.path == "src/handler.test.ts" && file.status == mehscan_core::FileStatus::Ignored
    }));

    let route_paths = result
        .evidence
        .iter()
        .filter(|item| item.kind == EvidenceKind::Entrypoint)
        .flat_map(|item| {
            item.context
                .http_routes
                .iter()
                .map(|route| route.path.as_str())
        })
        .collect::<BTreeSet<_>>();
    assert!(route_paths.contains("/api/items/[id]"));
    assert!(route_paths.contains("/api/webhooks/test"));
    assert!(!result.evidence.iter().any(|item| {
        item.kind == EvidenceKind::Entrypoint && item.location.path == "src/not-a-route.ts"
    }));

    for capability in [
        Capability::OutboundNetworkRequest,
        Capability::DatabaseQuery,
        Capability::HtmlOutput,
        Capability::Redirect,
    ] {
        assert!(
            result
                .security_paths
                .iter()
                .any(|path| path.capability == capability),
            "missing {capability:?}: {:#?}",
            result.security_paths
        );
    }
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::OutboundNetworkRequest
            && path
                .steps
                .iter()
                .any(|step| step.location.path == "src/app/api/webhooks/test/route.ts")
    }));
    assert!(!result.security_paths.iter().any(|path| {
        path.capability == Capability::Redirect
            && path
                .steps
                .iter()
                .any(|step| step.location.path == "src/app/api/safe-redirect/route.ts")
            && path.state != SecurityPathState::Protected
    }));

    let account = result
        .evidence
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Entrypoint
                && item.location.path == "src/app/api/account/route.ts"
        })
        .expect("authenticated route entrypoint");
    assert_eq!(
        account.context.http_routes[0].access,
        mehscan_core::HttpRouteAccess::Authenticated
    );
    assert_eq!(
        account.context.http_routes[0].guards,
        ["getUserFromRequest:rejects-401"]
    );

    for rule in [
        "typescript-nextjs-middleware-auth-coverage-review",
        "typescript-nextjs-route-authorization-review",
        "typescript-nextjs-client-controlled-privilege-assignment",
        "typescript-nextjs-whole-body-persistence",
        "typescript-nextjs-web-file-uploaded-path",
        "typescript-nextjs-graphql-introspection-review",
        "typescript-nextjs-graphql-complexity-review",
        "typescript-nextjs-client-controlled-financial-amount-review",
        "typescript-nextjs-read-check-write-race-review",
        "typescript-manual-jwt-weak-fallback-secret",
        "typescript-manual-jwt-without-expiry",
        "typescript-manual-jwt-alg-none-acceptance",
        "typescript-nextjs-auth-rate-limit-review",
        "typescript-nextjs-distinct-login-response-review",
        "typescript-nextjs-literal-default-credential",
        "typescript-nextjs-reset-token-response",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }
    assert!(!result.evidence.iter().any(|item| {
        item.rule_id == "typescript-nextjs-whole-body-persistence"
            && item.location.path == "src/app/api/safe-profile/route.ts"
    }));
    assert!(!result.evidence.iter().any(|item| {
        matches!(
            item.rule_id.as_str(),
            "typescript-nextjs-auth-rate-limit-review"
                | "typescript-nextjs-distinct-login-response-review"
                | "typescript-nextjs-literal-default-credential"
                | "typescript-nextjs-reset-token-response"
        ) && item.location.path.starts_with("safe/")
    }));
    assert!(!result.evidence.iter().any(|item| {
        item.rule_id == "typescript-nextjs-graphql-complexity-review"
            && item.location.path == "src/app/api/safe-graphql/route.ts"
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.cwe_candidates == ["CWE-915"]
            && path
                .steps
                .last()
                .is_some_and(|step| step.location.path == "src/app/api/profile/route.ts")
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.cwe_candidates == ["CWE-434", "CWE-22"]
            && path
                .steps
                .last()
                .is_some_and(|step| step.location.path == "src/app/api/upload/route.ts")
    }));
}
