use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, HttpRouteAccess};

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/javascript/fastify-demo")
}

#[test]
#[ignore = "requires the optional pinned official Fastify demo"]
fn locks_the_js5_fastify_clean_baseline() {
    let result = mehscan_engine::scan_path(corpus()).expect("Fastify demo should scan");

    assert_eq!(result.coverage.totals.discovered, 74);
    assert_eq!(result.coverage.totals.scanned, 34);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(
        (result.evidence.len(), result.security_paths.len()),
        (62, 0)
    );

    let fastify = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine.ends_with("bounded-fastify-boundary"))
        .collect::<Vec<_>>();
    assert_eq!(fastify.len(), 53);
    assert_eq!(
        fastify
            .iter()
            .filter(|item| item.kind == EvidenceKind::Entrypoint)
            .count(),
        14
    );
    assert_eq!(
        fastify
            .iter()
            .filter(|item| item.kind == EvidenceKind::Validation)
            .count(),
        13
    );
    assert!(fastify.iter().any(|item| {
        item.rule_id == "typescript-fastify-route-pre-handler"
            && item.capability == Capability::Authorization
            && item.context.http_routes[0].access == HttpRouteAccess::Unknown
            && !item.context.http_routes[0].guards.is_empty()
    }));
    for capability in [
        Capability::CookieConfiguration,
        Capability::CorsConfiguration,
        Capability::FileUpload,
        Capability::HttpHeaderOutput,
    ] {
        assert!(fastify.iter().any(|item| {
            item.kind == EvidenceKind::SecurityConfiguration && item.capability == capability
        }));
    }
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "typescript-secure-security-randomness-control"
            && item.location.path == "src/plugins/app/password-manager.ts"
            && item.location.start.line == 23
    }));
}
