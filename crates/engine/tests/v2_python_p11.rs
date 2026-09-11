use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p11")
}

#[test]
fn relates_only_request_controlled_resource_selectors_not_update_values_or_credentials() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 1);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let resource_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::ResourceAccess
                && path.cwe_candidates.iter().any(|cwe| cwe == "CWE-639")
        })
        .collect::<Vec<_>>();
    assert_eq!(resource_paths.len(), 1);
    assert!(
        resource_paths[0]
            .steps
            .last()
            .is_some_and(|step| step.location.start.line == 31)
    );
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "python-django-orm-resource-access"
            && item.location.start.line == 6
            && item.captures["filter"].text == "1"
    }));
    assert!(!result.evidence.iter().any(|item| {
        item.rule_id == "python-django-orm-resource-access"
            && matches!(item.location.start.line, 12 | 20 | 26)
    }));
}
