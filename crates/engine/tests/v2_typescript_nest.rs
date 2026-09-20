use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, HttpRouteAccess, RuntimeEnvironment};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-typescript-nest")
}

#[test]
fn catalogs_exact_nestjs_boundaries_aliases_guards_pipes_and_response_sinks() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("Nest fixture should scan");
    assert_eq!(result.coverage.totals.scanned, 5);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let nest = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine.ends_with("bounded-nestjs-boundary"))
        .collect::<Vec<_>>();
    let unexpected = nest
        .iter()
        .filter(|item| {
            item.location.path.ends_with("lookalike.ts")
                || item.context.runtime_environment != Some(RuntimeEnvironment::Server)
        })
        .map(|item| {
            (
                item.location.path.as_str(),
                item.rule_id.as_str(),
                item.context.runtime_environment,
            )
        })
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "unexpected Nest evidence: {unexpected:?}"
    );

    let counts = nest.iter().fold(BTreeMap::new(), |mut counts, item| {
        *counts.entry(item.kind).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(counts[&EvidenceKind::Entrypoint], 4);
    assert_eq!(counts[&EvidenceKind::Source], 4);
    assert_eq!(counts[&EvidenceKind::Guard], 3);
    assert_eq!(counts[&EvidenceKind::Validation], 3);
    assert_eq!(counts[&EvidenceKind::Sink], 2);

    let preview = nest
        .iter()
        .find(|item| {
            item.rule_id == "typescript-nestjs-request-parameter"
                && item.enclosing_symbol.as_deref() == Some("preview")
        })
        .expect("decorated body parameter source");
    let preview_route = &preview.context.http_routes[0];
    assert_eq!(preview_route.method, "POST");
    assert_eq!(preview_route.path, "/reports/preview");
    assert_eq!(preview_route.access, HttpRouteAccess::Unknown);
    assert_eq!(preview_route.guards, ["JwtAuthGuard", "RolesGuard"]);
    assert_eq!(preview.captures["selector"].text, "html");
    assert_eq!(
        preview
            .symbol_resolution
            .as_ref()
            .expect("aliased decorator resolution")
            .canonical,
        "Body"
    );

    let validation = nest
        .iter()
        .find(|item| {
            item.rule_id == "typescript-nestjs-validation-pipe"
                && item.tags.iter().any(|tag| tag == "transform:true")
        })
        .expect("exact ValidationPipe context");
    assert!(validation.tags.iter().any(|tag| tag == "whitelist:true"));
    assert!(
        validation
            .tags
            .iter()
            .any(|tag| tag == "forbid-non-whitelisted:true")
    );
    assert!(validation.tags.iter().any(|tag| tag == "transform:true"));
    let class_validation = nest
        .iter()
        .find(|item| {
            item.rule_id == "typescript-nestjs-validation-pipe"
                && !item.tags.iter().any(|tag| tag == "transform:true")
        })
        .expect("class ValidationPipe context");
    assert_eq!(
        class_validation.context.http_routes.len(),
        2,
        "class-level pipes apply context to every controller route"
    );
    let global_validation = nest
        .iter()
        .find(|item| item.rule_id == "typescript-nestjs-global-validation-pipe")
        .expect("global ValidationPipe context");
    assert!(
        global_validation
            .tags
            .iter()
            .any(|tag| tag == "global-pipe")
    );
    assert!(
        global_validation
            .tags
            .iter()
            .any(|tag| tag == "whitelist:true")
    );

    let unknown_guard = nest
        .iter()
        .find(|item| item.enclosing_symbol.as_deref() == Some("run"))
        .expect("custom-guard route remains visible");
    assert_eq!(
        unknown_guard.context.http_routes[0].access,
        HttpRouteAccess::Unknown,
        "arbitrary guard names must not prove authentication"
    );
    assert!(
        !nest
            .iter()
            .any(|item| item.location.path.ends_with("custom-context.ts")
                && item.kind == EvidenceKind::Validation),
        "custom pipes are not automatically treated as validation"
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::HtmlOutput | Capability::Redirect
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2);
    assert!(
        paths
            .iter()
            .any(|path| path.capability == Capability::HtmlOutput)
    );
    assert!(
        paths
            .iter()
            .any(|path| path.capability == Capability::Redirect)
    );
}
