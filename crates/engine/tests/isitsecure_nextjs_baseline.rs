use std::path::PathBuf;

use mehscan_core::Capability;

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/javascript/isitsecure/test-app")
}

#[test]
#[ignore = "requires the optional pinned isitsecure Next.js corpus"]
fn locks_the_js7_next_app_router_baseline() {
    let result = mehscan_engine::scan_path(corpus()).expect("Next.js test app should scan");

    assert_eq!(result.coverage.totals.discovered, 28);
    assert_eq!(result.coverage.totals.scanned, 24);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(
        (result.evidence.len(), result.security_paths.len()),
        (151, 15)
    );

    for (capability, path, line) in [
        (
            Capability::OutboundNetworkRequest,
            "src/app/api/avatar/route.ts",
            16,
        ),
        (
            Capability::OutboundNetworkRequest,
            "src/app/api/webhooks/test/route.ts",
            16,
        ),
        (
            Capability::DatabaseQuery,
            "src/app/api/auth/login/route.ts",
            11,
        ),
        (
            Capability::HtmlOutput,
            "src/app/api/tasks/search/route.ts",
            25,
        ),
    ] {
        assert!(result.security_paths.iter().any(|candidate| {
            candidate.capability == capability
                && candidate.steps.last().is_some_and(|step| {
                    step.location.path == path && step.location.start.line == line
                })
        }));
    }

    for rule in [
        "typescript-manual-jwt-alg-none-acceptance",
        "typescript-nextjs-middleware-auth-coverage-review",
        "typescript-nextjs-whole-body-persistence",
        "typescript-nextjs-web-file-uploaded-path",
        "typescript-nextjs-client-controlled-financial-amount-review",
        "typescript-nextjs-read-check-write-race-review",
        "typescript-nextjs-reset-token-response",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "typescript-secure-security-randomness-control"
            && item.location.path == "src/app/api/auth/reset/route.ts"
            && item.location.start.line == 19
    }));
}
