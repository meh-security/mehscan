use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, FileStatus};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c9")
}

#[test]
fn inventories_razor_escape_hatches_and_classifies_session_cookie_policy() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 7);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert!(result.security_paths.is_empty());

    let razor_files = result
        .coverage
        .files
        .iter()
        .filter(|file| file.path.ends_with(".cshtml"))
        .collect::<Vec<_>>();
    assert_eq!(razor_files.len(), 3);
    assert!(razor_files.iter().all(|file| {
        file.status == FileStatus::Scanned
            && file.language.is_none()
            && file
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no full Razor parser"))
    }));

    let raw = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-razor-html-raw-output")
        .collect::<Vec<_>>();
    assert_eq!(raw.len(), 2);
    assert_eq!(
        raw.iter()
            .filter(|item| item.location.path == "positive/Unsafe.cshtml")
            .count(),
        2
    );
    assert!(raw.iter().all(|item| {
        item.kind == EvidenceKind::Sink
            && item.capability == Capability::HtmlOutput
            && item.location.path != "control/Encoded.cshtml"
    }));
    let literal_control = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "csharp-razor-literal-raw-output-control")
        .expect("literal raw output should remain explicit control evidence");
    assert_eq!(literal_control.kind, EvidenceKind::Validation);
    assert_eq!(literal_control.location.path, "review/Literal.cshtml");

    let session = result
        .evidence
        .iter()
        .filter(|item| item.rule_id.starts_with("csharp-session-cookie-policy-"))
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts
                .entry((item.rule_id.as_str(), item.kind))
                .or_insert(0usize) += 1;
            counts
        });
    for expected in [
        (
            "csharp-session-cookie-policy-risk",
            EvidenceKind::SecurityConfiguration,
        ),
        (
            "csharp-session-cookie-policy-control",
            EvidenceKind::Validation,
        ),
        (
            "csharp-session-cookie-policy-review",
            EvidenceKind::SecurityConfiguration,
        ),
    ] {
        assert_eq!(session.get(&expected), Some(&1), "missing {expected:?}");
    }
    assert!(!result.evidence.iter().any(|item| {
        item.location.path == "control/Lookalike.cs"
            && item.rule_id.starts_with("csharp-session-cookie-policy-")
    }));
}
