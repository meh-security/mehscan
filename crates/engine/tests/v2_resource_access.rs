use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{
    Capability, EvidenceKind, HttpRouteAccess, ResourcePolicyState, SecurityPathState,
    SecurityPathStepKind,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-resource-access")
}

#[test]
fn reports_request_selected_unscoped_resources_and_retains_scoped_controls() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 8);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let observations = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::ResourceAccess)
        .collect::<Vec<_>>();
    assert_eq!(observations.len(), 7);
    assert!(observations.iter().all(|item| {
        item.kind == EvidenceKind::Sink
            && item.cwe_candidates == ["CWE-639"]
            && item.captures.contains_key("filter")
    }));
    assert_eq!(
        observations
            .iter()
            .filter(|item| item.location.path.starts_with("negative/"))
            .count(),
        4
    );

    let public_catalog = observations
        .iter()
        .find(|item| item.location.path.ends_with("public-catalog.ts"))
        .expect("paired public catalog item read");
    assert_eq!(
        public_catalog
            .context
            .resource_policy
            .as_ref()
            .map(|policy| policy.state),
        Some(ResourcePolicyState::PublicCatalog)
    );
    assert_eq!(public_catalog.context.http_routes.len(), 1);
    assert_eq!(public_catalog.context.http_routes[0].method, "GET");
    assert_eq!(
        public_catalog.context.http_routes[0].path,
        "/api/delivery-methods/:id"
    );
    assert_eq!(
        public_catalog.context.http_routes[0].access,
        HttpRouteAccess::Unknown
    );

    let authenticated = observations
        .iter()
        .find(|item| item.location.path.ends_with("authenticated-route.ts"))
        .expect("authenticated unscoped resource");
    assert_eq!(authenticated.context.http_routes.len(), 1);
    assert_eq!(
        authenticated.context.http_routes[0].access,
        HttpRouteAccess::Authenticated
    );
    assert_eq!(
        authenticated.context.http_routes[0].guards,
        ["security.isAuthorized"]
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::ResourceAccess)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 7);
    assert!(paths.iter().all(|path| {
        path.cwe_candidates == ["CWE-639"]
            && path
                .steps
                .first()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Source)
            && path
                .steps
                .last()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Sink)
    }));
    assert_eq!(
        paths
            .iter()
            .filter(|path| path
                .steps
                .iter()
                .all(|step| step.location.path.starts_with("positive/")))
            .count(),
        3
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path
                .steps
                .last()
                .is_some_and(|step| step.location.path.ends_with("owner-scoped.ts")))
            .count(),
        4,
        "request-controlled owner fields are not authorization proof"
    );
    assert!(paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| !step.location.path.ends_with("token-derived-owner.ts"))
    }));

    let states = paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        *counts.entry(path.state).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(states[&SecurityPathState::Direct], 6);
    assert_eq!(states[&SecurityPathState::Unknown], 1);
    assert!(paths.iter().any(|path| {
        path.state == SecurityPathState::Unknown
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "control_flow_context_not_modeled")
            && path.steps.iter().any(|step| {
                step.kind == SecurityPathStepKind::Assignment
                    && step.symbol.as_deref() == Some("id")
            })
    }));
}
