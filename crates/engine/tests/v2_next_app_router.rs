use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, ReviewReadiness, SecurityPathState};

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
    let financial = result
        .evidence
        .iter()
        .filter(|item| {
            item.rule_id == "typescript-nextjs-client-controlled-financial-amount-review"
        })
        .collect::<Vec<_>>();
    assert_eq!(financial.len(), 3, "{financial:#?}");
    assert!(financial.iter().any(|item| {
        item.location.path == "src/app/api/checkout/route.ts"
            && item.captures["request_field"].text == "price"
            && item.captures["effect_field"].text == "amount"
            && item.captures["financial_resource"].text == "\"orders\""
            && !item.captures.contains_key("authority_helper")
    }));
    assert!(financial.iter().any(|item| {
        item.location.path == "src/app/api/quoted-checkout/route.ts"
            && item.captures["request_field"].text == "submittedPrice"
            && item.captures["authority_helper"].text == "lookupPrice"
    }));
    assert!(financial.iter().any(|item| {
        item.location.path == "src/app/api/body-checkout/route.ts"
            && item.captures["request_field"].text == "total"
            && item.captures["supplied_value"].text == "submittedTotal"
            && item.captures["financial_resource"].text == "\"payments\""
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "typescript-nextjs-authoritative-financial-value-binding-control"
            && item.location.path == "src/app/api/safe-checkout/route.ts"
            && item.captures["authoritative_value"].text == "catalogPlan.price"
            && item.captures["authority_helper"].text == "loadPlan"
    }));
    assert!(
        !financial
            .iter()
            .any(|item| item.location.path == "src/app/api/safe-checkout/route.ts")
    );
    assert!(
        !financial
            .iter()
            .any(|item| item.location.path == "src/app/api/financial-lookalike/route.ts")
    );
    let transitions = result
        .evidence
        .iter()
        .filter(|item| {
            item.rule_id == "typescript-nextjs-client-controlled-state-transition-review"
        })
        .collect::<Vec<_>>();
    assert_eq!(transitions.len(), 2, "{transitions:#?}");
    assert!(transitions.iter().any(|item| {
        item.location.path == "src/app/api/orders/unsafe-state/route.ts"
            && item.captures["request_field"].text == "status"
            && item.captures["state_resource"].text == "\"orders\""
            && !item.captures.contains_key("transition_helper")
    }));
    assert!(transitions.iter().any(|item| {
        item.location.path == "src/app/api/orders/policy-state/route.ts"
            && item.captures["current_state"].text == "order.status"
            && item.captures["transition_helper"].text == "canTransitionOrder"
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "typescript-nextjs-explicit-state-transition-control"
            && item.location.path == "src/app/api/orders/guarded-state/route.ts"
            && item.captures["current_state"].text == "order.status"
    }));
    assert!(
        !transitions
            .iter()
            .any(|item| item.location.path == "src/app/api/orders/guarded-state/route.ts")
    );
    let shared_limits = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "typescript-nextjs-read-check-write-race-review")
        .collect::<Vec<_>>();
    assert_eq!(shared_limits.len(), 2, "{shared_limits:#?}");
    assert!(shared_limits.iter().any(|item| {
        item.location.path == "src/app/api/credits/redeem/route.ts"
            && item.captures["current_value"].text == "credits[0].balance"
            && item.captures["requested_delta"].text == "amount"
            && item.captures["derived_value"].text == "currentBalance - amount"
            && item.captures["persistence_helper"].text == "updateRow"
    }));
    assert!(shared_limits.iter().any(|item| {
        item.location.path == "src/app/api/inventory/reserve/route.ts"
            && item.captures["request_field"].text == "quantity"
            && item.captures["current_value"].text == "rows[0][\"stock\"]"
            && item.captures["state_resource"].text == "\"inventory\""
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "typescript-nextjs-atomic-shared-state-limit-control"
            && item.location.path == "src/app/api/inventory/atomic-reserve/route.ts"
            && item.captures["state_field"].text == "stock"
            && item.captures["request_field"].text == "quantity"
    }));
    assert!(
        !shared_limits
            .iter()
            .any(|item| { item.location.path == "src/app/api/inventory/atomic-reserve/route.ts" })
    );
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

#[test]
fn packages_only_missing_financial_authority_as_investigation() {
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("review job should build");
    let reviews = job
        .observation_reviews
        .iter()
        .filter(|review| {
            review.evidence.iter().any(|item| {
                item.rule_id == "typescript-nextjs-client-controlled-financial-amount-review"
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(reviews.len(), 3, "{reviews:#?}");

    let direct = reviews
        .iter()
        .find(|review| review.evidence[0].location.path.contains("/checkout/"))
        .expect("direct client amount review");
    assert_eq!(direct.investigation.readiness, ReviewReadiness::Assessment);
    assert!(direct.decision_facts.unresolved.is_empty());
    assert!(direct.decision_facts.established.iter().any(|fact| {
        fact.contains("request-body field `price`")
            && fact.contains("financial effect field `amount`")
    }));

    let quoted = reviews
        .iter()
        .find(|review| review.evidence[0].location.path.contains("quoted-checkout"))
        .expect("unresolved quoted amount review");
    assert_eq!(
        quoted
            .review_basis
            .as_ref()
            .expect("operation review contract")
            .relationship,
        "bounded_authoritative_value_binding_review"
    );
    assert_eq!(
        quoted.investigation.readiness,
        ReviewReadiness::Investigation
    );
    assert_eq!(quoted.decision_facts.unresolved.len(), 1);
    assert!(quoted.investigation.lookup_requests.iter().any(|lookup| {
        lookup.operation == "references"
            && lookup.arguments.get("symbol") == Some(&"lookupPrice".to_string())
    }));

    let transitions = job
        .observation_reviews
        .iter()
        .filter(|review| {
            review.evidence.iter().any(|item| {
                item.rule_id == "typescript-nextjs-client-controlled-state-transition-review"
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(transitions.len(), 2, "{transitions:#?}");
    let direct = transitions
        .iter()
        .find(|review| review.evidence[0].location.path.contains("unsafe-state"))
        .expect("direct transition review");
    assert_eq!(direct.investigation.readiness, ReviewReadiness::Assessment);
    assert!(direct.decision_facts.unresolved.is_empty());
    let policy = transitions
        .iter()
        .find(|review| review.evidence[0].location.path.contains("policy-state"))
        .expect("external transition policy review");
    assert_eq!(
        policy
            .review_basis
            .as_ref()
            .expect("state transition contract")
            .relationship,
        "bounded_state_transition_enforcement_review"
    );
    assert_eq!(
        policy.investigation.readiness,
        ReviewReadiness::Investigation
    );
    assert!(policy.investigation.lookup_requests.iter().any(|lookup| {
        lookup.operation == "references"
            && lookup.arguments.get("symbol") == Some(&"canTransitionOrder".to_string())
    }));

    let shared_limits = job
        .observation_reviews
        .iter()
        .filter(|review| {
            review.review_basis.as_ref().is_some_and(|basis| {
                basis.relationship == "bounded_shared_state_limit_enforcement_review"
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(shared_limits.len(), 2, "{shared_limits:#?}");
    assert!(shared_limits.iter().all(|review| {
        review.investigation.readiness == ReviewReadiness::Investigation
            && review.investigation.lookup_requests.iter().any(|lookup| {
                lookup.operation == "references"
                    && lookup.arguments.get("symbol") == Some(&"updateRow".to_string())
            })
            && review.decision_facts.established.iter().any(|fact| {
                fact.contains("read-check-derive-write sequence")
                    && fact.contains("database atomicity remains unresolved")
            })
    }));
}
