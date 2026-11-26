use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
#[ignore = "requires the optional local Rust vulnerable-app corpora"]
fn optional_rust_cors_is_review_context_not_a_security_path() {
    let root = workspace_root().join("apps/rust/rust-vulnerable-apps/cors");
    let result = mehscan_engine::scan_path(&root).expect("CORS corpus should scan");
    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let cors = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "rust-permissive-cors-review")
        .collect::<Vec<_>>();
    assert_eq!(cors.len(), 3);
    assert!(cors.iter().all(|item| {
        item.kind == EvidenceKind::SecurityConfiguration
            && item.capability == Capability::CorsConfiguration
    }));
    assert!(result.security_paths.is_empty());
}

#[test]
#[ignore = "requires the optional local Chop Shop corpus"]
fn optional_chop_shop_preserves_actix_positive_and_protected_truth() {
    let root = workspace_root().join("apps/rust/chop-shop");
    let result = mehscan_engine::scan_path(&root).expect("Chop Shop should scan");
    assert_eq!(result.coverage.totals.scanned, 7);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence.len(), 22);
    assert_eq!(result.security_paths.len(), 5);

    let expected = [
        (
            Capability::HtmlOutput,
            "src/main.rs",
            SecurityPathState::Propagated,
        ),
        (
            Capability::HtmlOutput,
            "src/contact_form.rs",
            SecurityPathState::Propagated,
        ),
        (
            Capability::DatabaseQuery,
            "src/sql_injection.rs",
            SecurityPathState::Propagated,
        ),
        (
            Capability::DatabaseQuery,
            "src/sell_parts.rs",
            SecurityPathState::Protected,
        ),
        (
            Capability::Logging,
            "src/contact_form.rs",
            SecurityPathState::Unknown,
        ),
    ];
    for (capability, path, state) in expected {
        assert!(
            result.security_paths.iter().any(|security_path| {
                security_path.capability == capability
                    && security_path.state == state
                    && security_path
                        .steps
                        .last()
                        .is_some_and(|step| step.location.path == path)
            }),
            "missing {state:?} {capability:?} path in {path}"
        );
    }
}
