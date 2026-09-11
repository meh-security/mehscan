use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-password-lifecycle")
}

#[test]
fn reports_bounded_password_change_and_storage_candidates_with_safe_controls() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 17);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let lifecycle = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-password-lifecycle")
        })
        .collect::<Vec<_>>();
    let vulnerable_sinks = lifecycle
        .iter()
        .filter(|item| item.kind == EvidenceKind::Sink)
        .collect::<Vec<_>>();
    assert_eq!(
        vulnerable_sinks
            .iter()
            .filter(|item| item.capability == Capability::Authentication)
            .count(),
        2
    );
    assert_eq!(
        vulnerable_sinks
            .iter()
            .filter(|item| item.capability == Capability::CryptographicHash)
            .count(),
        5
    );
    assert!(
        vulnerable_sinks
            .iter()
            .all(|item| item.location.path.starts_with("positive/"))
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-620"] || path.cwe_candidates == ["CWE-916"])
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 7);
    assert!(
        paths
            .iter()
            .all(|path| path.state == SecurityPathState::Unknown)
    );
    assert!(paths.iter().all(|path| {
        path.uncertainty_reasons
            .iter()
            .any(|reason| reason == "password_lifecycle_relationship_is_syntactic")
    }));

    let guards = lifecycle
        .iter()
        .filter(|item| item.kind == EvidenceKind::Guard)
        .collect::<Vec<_>>();
    assert_eq!(guards.len(), 4);
    assert!(
        guards
            .iter()
            .all(|item| item.location.path.starts_with("negative/"))
    );

    let strong = lifecycle
        .iter()
        .filter(|item| item.kind == EvidenceKind::SecurityConfiguration)
        .collect::<Vec<_>>();
    assert_eq!(strong.len(), 3);
    assert!(strong.iter().any(|item| {
        item.location.path == "negative/strong-helper.ts"
            && item
                .symbol_resolution
                .as_ref()
                .is_some_and(|resolution| resolution.canonical == "lib/strong.hashPassword")
    }));
    assert!(
        lifecycle
            .iter()
            .all(|item| item.location.path != "negative/unrelated-hash.ts")
    );

    let helper_sink = vulnerable_sinks
        .iter()
        .find(|item| item.location.path == "positive/weak-helper.ts")
        .expect("weak imported helper should resolve");
    assert!(helper_sink.tags.iter().any(|tag| tag == "algorithm:md5"));
    assert_eq!(
        helper_sink
            .symbol_resolution
            .as_ref()
            .expect("helper resolution")
            .canonical,
        "lib/weak.hash"
    );
}

#[test]
#[ignore = "requires the optional local Juice Shop corpus"]
fn juice_shop_password_lifecycle_targets_are_exact() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("juice-shop");
    let result = mehscan_engine::scan_path(root).expect("Juice Shop should scan");

    let lifecycle = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-password-lifecycle")
        })
        .collect::<Vec<_>>();

    let change = lifecycle
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Sink
                && item.capability == Capability::Authentication
                && item.location.path == "routes/changePassword.ts"
        })
        .expect("changePassword should produce a reauthentication candidate");
    assert_eq!(change.location.start.line, 51);
    let storage = lifecycle
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Sink
                && item.capability == Capability::CryptographicHash
                && item.location.path == "models/user.ts"
        })
        .expect("User password setter should produce a storage candidate");
    assert_eq!(storage.location.start.line, 76);
    assert!(storage.tags.iter().any(|tag| tag == "algorithm:md5"));

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-620"] || path.cwe_candidates == ["CWE-916"])
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().any(|path| {
        path.capability == Capability::Authentication
            && path.steps.last().is_some_and(|step| {
                step.location.path == "routes/changePassword.ts" && step.location.start.line == 51
            })
    }));
    assert!(paths.iter().any(|path| {
        path.capability == Capability::CryptographicHash
            && path.steps.last().is_some_and(|step| {
                step.location.path == "models/user.ts" && step.location.start.line == 76
            })
    }));
    assert!(lifecycle.iter().any(|item| {
        item.kind == EvidenceKind::Guard
            && item.location.path == "routes/resetPassword.ts"
            && item.tags.iter().any(|tag| tag == "recovery-answer")
    }));
}
