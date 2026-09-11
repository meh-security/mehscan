use std::path::PathBuf;

use mehscan_core::{Capability, HttpRouteAccess};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p2")
}

#[test]
fn models_django_drf_routes_request_shapes_and_access_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let handlers = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-django-handler-entrypoint")
        .collect::<Vec<_>>();
    assert_eq!(handlers.len(), 5);
    assert!(handlers.iter().any(|item| {
        item.enclosing_symbol.as_deref() == Some("get")
            && item.context.http_routes.iter().any(|route| {
                route.method == "GET"
                    && route.path == "/api/items/(?P<item_id>[0-9]+)"
                    && route.access == HttpRouteAccess::Authenticated
            })
    }));
    assert!(handlers.iter().any(|item| {
        item.enclosing_symbol.as_deref() == Some("upload")
            && item.context.http_routes.iter().any(|route| {
                route.path == "/api/upload/<slug:slug>"
                    && route.method == "POST"
                    && route.access == HttpRouteAccess::Authenticated
            })
    }));
    assert!(handlers.iter().any(|item| {
        item.context.http_routes.iter().any(|route| {
            route.path == "/api/admin"
                && route.method == "GET"
                && route.access == HttpRouteAccess::RoleRestricted
        })
    }));
    assert!(handlers.iter().any(|item| {
        item.context.http_routes.iter().any(|route| {
            route.path == "/api/public"
                && route.method == "GET"
                && route.access == HttpRouteAccess::Unknown
        })
    }));

    let route_parameters = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-django-route-parameter")
        .collect::<Vec<_>>();
    assert_eq!(route_parameters.len(), 3);
    assert!(route_parameters.iter().all(|item| {
        item.capability == Capability::HttpRequestData && !item.context.http_routes.is_empty()
    }));

    let request_sources = result
        .evidence
        .iter()
        .filter(|item| {
            item.rule_id == "python-http-request-data" && item.location.path == "api/views.py"
        })
        .collect::<Vec<_>>();
    assert_eq!(request_sources.len(), 8);
    assert!(request_sources.iter().all(|item| {
        item.context
            .http_routes
            .iter()
            .any(|route| route.path.starts_with("/api/"))
    }));

    assert!(!result.evidence.iter().any(|item| {
        item.location.path == "lookalikes.py"
            && matches!(
                item.capability,
                Capability::HttpRequestData | Capability::HttpRequestHandling
            )
    }));
}
