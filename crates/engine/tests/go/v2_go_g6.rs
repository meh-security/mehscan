use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn models_go_ldap_filter_transport_logging_and_output_boundaries() {
    let result = mehscan_engine::scan_path(fixture("v2-go-g6-ldap"))
        .expect("positive LDAP fixture should scan");
    let counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    for rule in [
        "go-http-form-map-value-source",
        "go-ldap-search-request-filter",
        "go-ldap-filter-query-summary",
        "go-ldap-plaintext-transport-review",
        "go-ldap-bind-password-logging-review",
        "go-ldap-result-value-source",
        "go-fprintf-http-html-output",
    ] {
        assert!(counts.contains_key(rule), "missing {rule}: {counts:?}");
    }
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| {
                path.capability == Capability::LdapQuery && path.state == SecurityPathState::Unknown
            })
            .count(),
        2,
        "both same-branch and split-branch LDAP paths should remain reviewable"
    );
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::HtmlOutput && path.state == SecurityPathState::Unknown
    }));
}

#[test]
fn preserves_exact_ldap_and_html_controls() {
    let result = mehscan_engine::scan_path(fixture("v2-go-g6-ldap-safe"))
        .expect("safe LDAP fixture should scan");
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "go-ldap-filter-encoding-control"
            && item.kind == EvidenceKind::Sanitizer
            && item.capability == Capability::LdapFilterEncoding
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "go-ldap-tls-transport-control" && item.cwe_candidates.is_empty()
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "go-http-redirect"
            && item.capability == Capability::RedirectDestinationValidation
            && item.cwe_candidates.is_empty()
    }));
    assert!(result.evidence.iter().all(|item| {
        !matches!(
            item.rule_id.as_str(),
            "go-ldap-plaintext-transport-review" | "go-ldap-bind-password-logging-review"
        )
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::LdapQuery && path.state == SecurityPathState::Protected
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::HtmlOutput && path.state == SecurityPathState::Protected
    }));
}

#[test]
fn includes_unique_ldap_helper_definition_in_path_review_context() {
    let job = mehscan_engine::investigation::build_all_path_review_jobs(
        &fixture("v2-go-g6-ldap"),
        Some(8),
        false,
    )
    .expect("LDAP review jobs should build");
    let ldap_reviews = job
        .reviews
        .iter()
        .filter(|review| review.candidate.sink.rule_id == "go-ldap-filter-query-summary");
    for review in ldap_reviews {
        assert!(review.facts.iter().any(|fact| {
            fact.excerpt.contains("func (c *Client) search")
                && fact.excerpt.contains("NewSearchRequest")
                && fact.excerpt.contains("filter")
        }));
    }
}
