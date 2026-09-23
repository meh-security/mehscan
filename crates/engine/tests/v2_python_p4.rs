use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, ResourcePolicyState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p4")
}

#[test]
fn distinguishes_django_object_policy_and_sensitive_writes() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let orm = result
        .evidence
        .iter()
        .filter(|item| item.rule_id.starts_with("python-django-orm-"))
        .collect::<Vec<_>>();
    assert_eq!(orm.len(), 3);
    assert_eq!(
        orm.iter()
            .filter(|item| item.kind == EvidenceKind::Sink)
            .count(),
        3
    );
    // The fixture's jwt_auth_required decorator is a no-op. Its name cannot
    // prove that the user parameter is an authenticated owner identity.
    assert_eq!(
        orm.iter()
            .filter(|item| {
                item.context
                    .resource_policy
                    .as_ref()
                    .is_some_and(|policy| policy.state == ResourcePolicyState::OwnerScoped)
            })
            .count(),
        0
    );

    let mutations = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-django-sensitive-field-mutation")
        .collect::<Vec<_>>();
    assert_eq!(mutations.len(), 1);
    assert!(mutations[0].tags.iter().any(|tag| tag == "field:balance"));
    assert_eq!(
        mutations[0].captures["nearby_rejecting_validation"].text,
        "account.balance < account.unit_price"
    );

    let serializer_writes = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-drf-sensitive-serializer-write")
        .collect::<Vec<_>>();
    assert_eq!(serializer_writes.len(), 1);
    assert!(
        serializer_writes[0]
            .tags
            .iter()
            .any(|tag| tag == "field:role")
    );
    assert!(
        serializer_writes[0]
            .tags
            .iter()
            .any(|tag| tag == "field:is_staff")
    );

    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::ResourceAccess
            && path.cwe_candidates.iter().any(|cwe| cwe == "CWE-639")
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::ResourceAccess
            && path.cwe_candidates.iter().any(|cwe| cwe == "CWE-915")
    }));

    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&fixture_root(), None, Some(100))
            .expect("Python business-invariant reviews should build");
    let mutation_review = jobs
        .reviews
        .iter()
        .find(|review| review.candidate.sink.rule_id == "python-django-sensitive-field-mutation")
        .expect("sensitive mutation path review");
    assert!(
        mutation_review
            .review_basis
            .as_ref()
            .expect("path review basis")
            .security_question
            .contains("sign, multiplicity, units and range")
    );
    assert!(
        mutation_review
            .open_questions
            .iter()
            .any(|question| question.contains("a check over one unit"))
    );
}
