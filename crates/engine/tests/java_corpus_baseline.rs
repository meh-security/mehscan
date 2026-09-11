use std::path::PathBuf;

use mehscan_core::SecurityPathState;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/crAPI/services/identity")
}

#[test]
#[ignore = "requires the optional local crAPI Java identity corpus"]
fn optional_crapi_java_identity_baseline_matches_when_requested() {
    let root = corpus_root();
    assert!(
        root.join("build.gradle.kts").is_file(),
        "missing {}",
        root.display()
    );

    let result = mehscan_engine::scan_path(root).expect("crAPI Java identity should scan");
    assert_eq!(result.coverage.totals.scanned, 89);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence.len(), 188);
    assert_eq!(result.security_paths.len(), 6);

    for (cwe, state, path, line) in [
        (
            "CWE-78",
            SecurityPathState::Unknown,
            "src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java",
            244,
        ),
        (
            "CWE-639",
            SecurityPathState::Propagated,
            "src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java",
            169,
        ),
        (
            "CWE-639",
            SecurityPathState::Propagated,
            "src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java",
            186,
        ),
        (
            "CWE-639",
            SecurityPathState::Unknown,
            "src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java",
            222,
        ),
        (
            "CWE-639",
            SecurityPathState::Unknown,
            "src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java",
            180,
        ),
        (
            "CWE-639",
            SecurityPathState::Propagated,
            "src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java",
            211,
        ),
    ] {
        assert!(
            result.security_paths.iter().any(|candidate| {
                candidate.cwe_candidates == [cwe]
                    && candidate.state == state
                    && candidate.steps.last().is_some_and(|step| {
                        step.location.path == path && step.location.start.line == line
                    })
            }),
            "missing {state:?} {cwe} path at {path}:{line}"
        );
    }
}
