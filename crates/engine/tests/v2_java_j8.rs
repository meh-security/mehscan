use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j8")
}

#[test]
fn models_exact_java_filesystem_archive_and_containment_policy() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 7);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let j8 = result
        .evidence
        .iter()
        .filter(|evidence| evidence.provenance.engine == "mehscan java-filesystem-archive-policy 1")
        .collect::<Vec<_>>();
    let counts = j8.iter().fold(BTreeMap::new(), |mut counts, evidence| {
        *counts.entry(evidence.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });
    assert!(
        !result
            .evidence
            .iter()
            .any(|evidence| evidence.location.path == "Lookalikes.java")
    );
    assert_eq!(counts["java-filesystem-read"], 2);
    assert_eq!(counts["java-filesystem-write"], 7);
    assert_eq!(counts["java-spring-multipart-transfer-to-filesystem"], 2);
    assert_eq!(counts["java-spring-multipart-file-storage"], 2);
    assert_eq!(counts["java-path-canonicalization"], 7);
    assert_eq!(counts["java-path-containment-check"], 3);
    assert_eq!(counts["java-zip-entry-name"], 2);
    assert_eq!(counts["java-jar-entry-name"], 1);
    assert_eq!(counts["java-commons-zip-entry-name"], 1);
    assert_eq!(counts["java-tar-entry-name"], 1);
    assert_eq!(counts["java-symbolic-link-check-control"], 1);
    assert_eq!(counts["java-no-follow-links-control"], 1);
    assert_eq!(counts["java-filesystem-overwrite-enabled"], 2);
    for rule in [
        "java-file-stream-read",
        "java-file-reader-read",
        "java-random-access-file",
        "java-file-stream-write",
        "java-file-writer-write",
        "java-spring-filesystem-resource",
    ] {
        assert_eq!(counts[rule], 1, "{rule}");
    }
    assert_eq!(counts["java-random-access-file-write"], 1);
    assert_eq!(j8.len(), 39);

    let archive_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::FilesystemWrite
                && path.cwe_candidates == ["CWE-22"]
                && result.evidence.iter().any(|evidence| {
                    evidence.id == path.source_evidence_id
                        && matches!(
                            evidence.rule_id.as_str(),
                            "java-zip-entry-name"
                                | "java-jar-entry-name"
                                | "java-commons-zip-entry-name"
                                | "java-tar-entry-name"
                        )
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(archive_paths.len(), 5);
    assert_eq!(
        archive_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Propagated)
            .count(),
        4
    );
    assert_eq!(
        archive_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        1
    );
}
