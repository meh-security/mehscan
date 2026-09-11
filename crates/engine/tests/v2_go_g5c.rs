use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn inventories_symlink_following_and_world_writable_modes() {
    let result = mehscan_engine::scan_path(fixture("v2-go-g5c-filesystem"))
        .expect("positive filesystem fixture should scan");

    let symlink_reviews = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "go-os-create-symlink-following-review")
        .collect::<Vec<_>>();
    assert_eq!(symlink_reviews.len(), 1);
    assert_eq!(symlink_reviews[0].cwe_candidates, ["CWE-59"]);
    assert_eq!(symlink_reviews[0].capability, Capability::FilesystemWrite);

    let modes = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "go-world-writable-directory-mode")
        .collect::<Vec<_>>();
    assert_eq!(modes.len(), 2);
    assert!(modes.iter().all(|item| {
        item.kind == EvidenceKind::SecurityConfiguration && item.cwe_candidates == ["CWE-732"]
    }));
}

#[test]
fn recognizes_exclusive_creation_and_non_world_writable_modes() {
    let result = mehscan_engine::scan_path(fixture("v2-go-g5c-filesystem-safe"))
        .expect("safe filesystem fixture should scan");

    assert!(result.evidence.iter().all(|item| {
        !matches!(
            item.rule_id.as_str(),
            "go-os-create-symlink-following-review" | "go-world-writable-directory-mode"
        )
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "go-openfile-exclusive-create-control"
            && item.kind == EvidenceKind::Validation
            && item.cwe_candidates.is_empty()
    }));
}
