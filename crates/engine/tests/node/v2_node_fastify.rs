use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, HttpRouteAccess, RuntimeEnvironment};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-fastify")
}

#[test]
fn catalogs_exact_fastify_routes_sources_schemas_guards_replies_and_plugins() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("Fastify fixture should scan");
    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let fastify = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine.ends_with("bounded-fastify-boundary"))
        .collect::<Vec<_>>();
    assert!(!fastify.is_empty());
    assert!(fastify.iter().all(|item| {
        !item.location.path.ends_with("lookalike.ts")
            && item.context.runtime_environment == Some(RuntimeEnvironment::Server)
    }));

    assert_eq!(
        fastify
            .iter()
            .filter(|item| item.kind == EvidenceKind::Entrypoint)
            .count(),
        5
    );
    assert!(fastify.iter().any(|item| {
        item.kind == EvidenceKind::Validation && item.tags.iter().any(|tag| tag == "query-schema")
    }));
    assert!(fastify.iter().any(|item| {
        item.kind == EvidenceKind::Guard
            && item.capability == Capability::Authorization
            && item.context.http_routes[0].access == HttpRouteAccess::Unknown
            && !item.context.http_routes[0].guards.is_empty()
    }));
    assert!(fastify.iter().any(|item| {
        item.kind == EvidenceKind::Guard && item.rule_id == "typescript-fastify-lifecycle-guard"
    }));
    assert_eq!(
        fastify
            .iter()
            .filter(|item| item.kind == EvidenceKind::SecurityConfiguration)
            .count(),
        5,
        "three plugins plus HTML and text response media types"
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::HtmlOutput | Capability::Redirect | Capability::DynamicCodeExecution
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 3, "{paths:#?}");
    assert!(paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path.starts_with("positive/"))
    }));
    assert!(!result.security_paths.iter().any(|path| {
        path.steps
            .iter()
            .any(|step| step.location.path.starts_with("safe/"))
    }));
}
