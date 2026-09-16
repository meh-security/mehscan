use std::path::PathBuf;

use mehscan_core::SecurityPathState;

fn corpus(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../mehscan-internal/corpus-cache/apps/c-cpp")
        .join(version)
        .join("src")
}

#[test]
#[ignore = "requires the optional pinned Redis CVE-2026-23479 vulnerable/fixed corpus pair"]
fn optional_redis_pair_tracks_documented_client_invalidation_contract() {
    for (version, expected_state, expected_sink_line) in [
        (
            "redis-cve-2026-23479-vulnerable",
            SecurityPathState::Unknown,
            703,
        ),
        (
            "redis-cve-2026-23479-fixed",
            SecurityPathState::Protected,
            709,
        ),
    ] {
        let target = corpus(version);
        assert!(
            target.is_dir(),
            "optional corpus is missing: {}",
            target.display()
        );
        let result = mehscan_engine::scan_path(&target).expect("Redis src should scan");
        let paths = result
            .security_paths
            .iter()
            .filter(|path| {
                path.provenance.engine == "mehscan c-family documented-invalidation relationship 1"
            })
            .collect::<Vec<_>>();
        assert_eq!(
            paths.len(),
            4,
            "unexpected relationship count for {version}"
        );
        let cve_path = paths
            .iter()
            .find(|path| {
                result.evidence.iter().any(|item| {
                    item.id == path.source_evidence_id
                        && item.location.path == "blocked.c"
                        && item.location.start.line == 702
                })
            })
            .expect("CVE call-site relationship");
        assert_eq!(cve_path.state, expected_state);
        let sink = result
            .evidence
            .iter()
            .find(|item| item.id == cve_path.sink_evidence_id)
            .expect("CVE relationship sink");
        assert_eq!(sink.location.start.line, expected_sink_line);

        let unrelated_unknown = paths.iter().any(|path| {
            path.state == SecurityPathState::Unknown
                && result.evidence.iter().any(|item| {
                    item.id == path.source_evidence_id && item.location.path != "blocked.c"
                })
        });
        assert!(
            !unrelated_unknown,
            "unrelated Redis contract noise in {version}"
        );
    }
}
