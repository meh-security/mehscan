use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, HttpRouteAccess, RuntimeEnvironment};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-serverless-typescript")
}

#[test]
fn resolves_only_exact_exported_or_registered_serverless_http_boundaries() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 9);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let evidence = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-serverless-boundary")
        })
        .collect::<Vec<_>>();
    assert!(!evidence.is_empty());
    assert!(evidence.iter().all(|item| {
        item.location.path.starts_with("positive/")
            && item.context.runtime_environment == Some(RuntimeEnvironment::Server)
    }));

    let entrypoints = evidence
        .iter()
        .filter(|item| item.kind == EvidenceKind::Entrypoint)
        .collect::<Vec<_>>();
    assert_eq!(entrypoints.len(), 8, "{entrypoints:#?}");

    let canonical = evidence
        .iter()
        .filter(|item| item.kind == EvidenceKind::Source)
        .filter_map(|item| item.symbol_resolution.as_ref())
        .map(|symbol| symbol.canonical.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        canonical,
        [
            "@azure/functions.HttpRequest",
            "@vercel/node.VercelRequest",
            "aws-lambda.APIGatewayProxyEvent",
            "next.NextApiRequest",
            "next/server.NextRequest",
        ]
        .into_iter()
        .collect()
    );

    let azure_public = entrypoints
        .iter()
        .find(|item| {
            item.context
                .http_routes
                .iter()
                .any(|route| route.path == "/danger/{id}")
        })
        .expect("named Azure registration");
    assert_eq!(azure_public.context.http_routes[0].method, "POST");
    assert_eq!(
        azure_public.context.http_routes[0].access,
        HttpRouteAccess::Unknown
    );
    let azure_private = entrypoints
        .iter()
        .find(|item| {
            item.context
                .http_routes
                .iter()
                .any(|route| route.path == "/private")
        })
        .expect("inline Azure registration");
    assert_eq!(
        azure_private.context.http_routes[0].access,
        HttpRouteAccess::Unknown
    );
    assert_eq!(
        azure_private.context.http_routes[0].guards,
        ["azure_auth_level:function"]
    );
    assert!(entrypoints.iter().any(|item| {
        item.context
            .http_routes
            .iter()
            .any(|route| route.method == "POST" && route.path == "/api/items")
    }));

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::DynamicCodeExecution)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 8, "{paths:#?}");
    assert!(paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path.starts_with("positive/"))
    }));
}
