use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c8")
}

#[test]
fn classifies_factory_commands_and_identity_account_policy() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let command_sinks = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-sql-command-text")
        .collect::<Vec<_>>();
    assert_eq!(command_sinks.len(), 2);
    assert!(
        command_sinks
            .iter()
            .all(|item| !item.location.path.ends_with("Lookalikes.cs"))
    );

    let sql_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::DatabaseQuery)
        .collect::<Vec<_>>();
    assert_eq!(sql_paths.len(), 1);
    assert_eq!(sql_paths[0].state, SecurityPathState::Propagated);
    assert!(
        sql_paths[0]
            .steps
            .last()
            .is_some_and(|sink| sink.location.path == "positive/FactoryAndIdentity.cs")
    );

    let identity = result
        .evidence
        .iter()
        .filter(|item| {
            item.rule_id.starts_with("csharp-identity-")
                && item.capability == Capability::Authentication
        })
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts
                .entry((item.rule_id.as_str(), item.kind))
                .or_insert(0usize) += 1;
            counts
        });
    for expected in [
        (
            "csharp-identity-weak-password-policy",
            EvidenceKind::SecurityConfiguration,
        ),
        (
            "csharp-identity-weak-lockout-policy",
            EvidenceKind::SecurityConfiguration,
        ),
        (
            "csharp-identity-password-length-control",
            EvidenceKind::Validation,
        ),
        ("csharp-identity-lockout-control", EvidenceKind::Validation),
        (
            "csharp-identity-password-policy-review",
            EvidenceKind::SecurityConfiguration,
        ),
        (
            "csharp-identity-lockout-policy-review",
            EvidenceKind::SecurityConfiguration,
        ),
    ] {
        assert_eq!(identity.get(&expected), Some(&1), "missing {expected:?}");
    }
    assert!(result.evidence.iter().all(|item| {
        !item.location.path.ends_with("Lookalikes.cs")
            || (!item.rule_id.starts_with("csharp-identity-")
                && item.rule_id != "csharp-sql-command-text")
    }));
}
