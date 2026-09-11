use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, HttpRouteAccess};

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/javascript/nextjs-vulnerable")
}

#[test]
#[ignore = "requires the optional pinned Next.js Pages Router corpus"]
fn locks_the_js8_next_pages_and_nextauth_baseline() {
    let result = mehscan_engine::scan_path(corpus()).expect("Pages Router corpus should scan");

    assert_eq!(result.coverage.totals.discovered, 20);
    assert_eq!(result.coverage.totals.scanned, 13);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!((result.evidence.len(), result.security_paths.len()), (3, 0));

    let credential = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "javascript-nextauth-hardcoded-credentials")
        .expect("hardcoded NextAuth credential provider");
    assert_eq!(credential.kind, EvidenceKind::SecurityConfiguration);
    assert_eq!(credential.capability, Capability::Authentication);
    assert_eq!(
        credential.context.http_routes[0].path,
        "/api/auth/[...nextauth]"
    );
    assert_eq!(
        credential.captures["password_literal"].text,
        "<redacted fixed credential>"
    );

    let middleware = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "javascript-nextauth-middleware-token-guard")
        .expect("middleware token guard");
    assert_eq!(middleware.kind, EvidenceKind::Guard);
    assert_eq!(
        middleware.context.http_routes[0].access,
        HttpRouteAccess::Authenticated
    );

    let review =
        mehscan_engine::investigation::build_all_path_review_jobs(&corpus(), Some(8), false)
            .expect("Pages Router review pack");
    assert!(review.reviews.is_empty());
    assert_eq!(review.observation_reviews.len(), 1);
    assert!(
        review.observation_reviews[0]
            .facts
            .iter()
            .all(|fact| !fact.excerpt.contains("password === 'password'"))
    );
}
