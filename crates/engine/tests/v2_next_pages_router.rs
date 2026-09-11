use std::path::PathBuf;

use mehscan_core::{EvidenceKind, HttpRouteAccess};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-next-pages-router")
}

#[test]
fn models_next_pages_api_ssr_nextauth_and_middleware_without_lookalikes() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);

    let hardcoded = result
        .evidence
        .iter()
        .filter(|item| item.rule_id.ends_with("nextauth-hardcoded-credentials"))
        .collect::<Vec<_>>();
    assert_eq!(hardcoded.len(), 1, "{:#?}", result.evidence);
    assert_eq!(
        hardcoded[0].location.path,
        "pages/api/auth/[...nextauth].js"
    );
    assert_eq!(
        hardcoded[0].captures["password_literal"].text,
        "<redacted fixed credential>"
    );
    assert_eq!(
        hardcoded[0].context.http_routes[0].path,
        "/api/auth/[...nextauth]"
    );
    assert!(!result.evidence.iter().any(|item| {
        item.rule_id.ends_with("nextauth-hardcoded-credentials")
            && (item.location.path.starts_with("safe/") || item.location.path == "lookalike.js")
    }));

    let middleware = result
        .evidence
        .iter()
        .find(|item| item.rule_id.ends_with("nextauth-middleware-token-guard"))
        .expect("exact NextAuth middleware guard");
    assert_eq!(middleware.kind, EvidenceKind::Guard);
    assert_eq!(
        middleware.context.http_routes[0].access,
        HttpRouteAccess::Authenticated
    );

    let api = result
        .evidence
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Entrypoint && item.location.path == "pages/api/items/[id].js"
        })
        .expect("Pages API entrypoint");
    assert_eq!(api.context.http_routes[0].path, "/api/items/[id]");
    assert_eq!(api.context.http_routes[0].method, "GET");
    assert!(result.evidence.iter().any(|item| {
        item.kind == EvidenceKind::Source
            && item.location.path == "pages/api/items/[id].js"
            && item
                .captures
                .get("value")
                .is_some_and(|value| value.text == "req.query.id")
    }));

    let account = result
        .evidence
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Entrypoint
                && item.location.path == "safe/pages/api/account.js"
        })
        .expect("authenticated Pages API entrypoint");
    assert_eq!(
        account.context.http_routes[0].access,
        HttpRouteAccess::Authenticated
    );

    let ssr = result
        .evidence
        .iter()
        .find(|item| item.rule_id.ends_with("nextjs-pages-ssr-entrypoint"))
        .expect("Pages SSR entrypoint");
    assert_eq!(ssr.context.http_routes[0].path, "/profile");
    assert!(result.evidence.iter().any(|item| {
        item.rule_id.ends_with("nextjs-pages-ssr-request-source")
            && item
                .captures
                .get("value")
                .is_some_and(|value| value.text == "context.query.tab")
    }));

    let review =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(6), false)
            .expect("Pages Router review pack");
    let credential_review = review
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id.ends_with("nextauth-hardcoded-credentials"))
        })
        .expect("hardcoded credentials should be reviewable");
    assert!(
        credential_review
            .facts
            .iter()
            .all(|fact| !fact.excerpt.contains("fixed-password"))
    );
    assert!(
        credential_review
            .facts
            .iter()
            .any(|fact| fact.excerpt.contains("**************"))
    );
}
