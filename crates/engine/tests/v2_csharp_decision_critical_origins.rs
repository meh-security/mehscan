use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-decision-critical-origins")
}

#[test]
fn retains_unknown_origin_only_for_strong_csharp_interpreter_boundaries() {
    let root = fixture_root();
    let result = mehscan_engine::scan_path(&root).expect("fixture should scan");
    let marked = result
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Sink
                && item
                    .tags
                    .iter()
                    .any(|tag| tag == "review-origin:decision-critical")
        })
        .collect::<Vec<_>>();

    for rule_id in [
        "csharp-aspnet-explicit-html-output",
        "csharp-razor-html-raw-output",
        "csharp-dynamic-code",
        "csharp-binaryformatter-deserialization",
        "csharp-extended-nosql-json",
        "csharp-directory-searcher-filter",
        "csharp-process-start",
        "csharp-process-start-info",
    ] {
        assert!(
            marked.iter().any(|item| item.rule_id == rule_id),
            "missing decision-critical marker for {rule_id}: {marked:#?}"
        );
    }

    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "csharp-html-output"
            && !item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "csharp-extended-nosql-query"
            && !item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
    }));
    assert!(result.evidence.iter().any(|item| {
        item.capability == Capability::ProcessExecution
            && item.captures.get("command").is_some_and(|capture| {
                capture.text.contains("tool.exe")
                    && !item
                        .tags
                        .iter()
                        .any(|tag| tag == "review-origin:decision-critical")
            })
    }));
    assert!(result.evidence.iter().any(|item| {
        item.capability == Capability::LdapQuery
            && item
                .captures
                .get("filter")
                .is_some_and(|capture| capture.text == "\"(objectClass=user)\"")
            && !item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
    }));

    let reviews = mehscan_engine::investigation::build_path_review_jobs(&root, Some(8), Some(100))
        .expect("review jobs should build");
    let critical_reviews = reviews
        .observation_reviews
        .iter()
        .filter(|review| {
            review.evidence.iter().any(|item| {
                item.tags
                    .iter()
                    .any(|tag| tag == "review-origin:decision-critical")
            })
        })
        .collect::<Vec<_>>();

    assert!(!critical_reviews.is_empty());
    let relationships = critical_reviews
        .iter()
        .filter_map(|review| review.review_basis.as_ref())
        .map(|basis| basis.relationship.as_str())
        .collect::<BTreeSet<_>>();
    for relationship in [
        "bounded_trusted_html_interpretation",
        "bounded_dynamic_executable_selection",
        "bounded_shell_command_interpretation",
        "bounded_dynamic_code_interpretation",
        "bounded_executable_object_deserialization",
        "bounded_raw_nosql_interpretation",
        "bounded_ldap_filter_interpretation",
    ] {
        assert!(
            relationships.contains(relationship),
            "missing {relationship}: {relationships:#?}"
        );
    }
    for review in critical_reviews {
        let encoded_ldap = review
            .evidence
            .iter()
            .any(|item| item.rule_id == "csharp-antixss-filter-applied-to-ldap-filter");
        if encoded_ldap {
            assert!(review.decision_facts.unresolved.is_empty(), "{review:#?}");
            assert!(!review.decision_facts.effective_controls.is_empty());
        } else {
            assert_eq!(review.decision_facts.unresolved.len(), 1, "{review:#?}");
        }
    }
}
