use std::path::PathBuf;

use mehscan_core::SecurityPathState;

fn corpus(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../mehscan-internal/corpus-cache/apps/c-cpp")
        .join(version)
        .join("modules/vector-sets/vset.c")
}

#[test]
#[ignore = "requires the optional pinned Redis CVE-2026-25243 vulnerable/fixed corpus pair"]
fn optional_redis_pair_tracks_fixed_layout_blob_and_arithmetic_extents() {
    for (
        version,
        expected_state,
        expected_source_line,
        expected_sink_line,
        expected_extent_sink_line,
    ) in [
        (
            "redis-cve-2026-25243-vulnerable",
            SecurityPathState::Unknown,
            1996,
            1998,
            1990,
        ),
        (
            "redis-cve-2026-25243-fixed",
            SecurityPathState::Protected,
            2021,
            2034,
            2017,
        ),
    ] {
        let target = corpus(version);
        assert!(
            target.is_file(),
            "optional corpus is missing: {}",
            target.display()
        );
        let result =
            mehscan_engine::scan_path(&target).expect("Redis vector-set source should scan");
        let paths = result
            .security_paths
            .iter()
            .filter(|path| {
                path.provenance.engine == "mehscan c-family serialized-blob extent relationship 1"
            })
            .collect::<Vec<_>>();
        assert_eq!(
            paths.len(),
            1,
            "unexpected relationship count for {version}"
        );
        let path = paths[0];
        assert_eq!(path.state, expected_state);
        assert_eq!(path.cwe_candidates, ["CWE-20", "CWE-125"]);
        let source = result
            .evidence
            .iter()
            .find(|item| item.id == path.source_evidence_id)
            .expect("serialized blob source");
        let sink = result
            .evidence
            .iter()
            .find(|item| item.id == path.sink_evidence_id)
            .expect("fixed-layout copy sink");
        assert_eq!(source.location.start.line, expected_source_line);
        assert_eq!(sink.location.start.line, expected_sink_line);
        assert_eq!(
            path.protection_evidence_ids.len(),
            usize::from(expected_state == SecurityPathState::Protected)
        );

        let extent_paths = result
            .security_paths
            .iter()
            .filter(|path| {
                path.provenance.engine == "mehscan c-family loaded-memory-extent relationship 1"
            })
            .collect::<Vec<_>>();
        assert_eq!(
            extent_paths.len(),
            1,
            "unexpected loaded-memory extent count for {version}"
        );
        let extent_path = extent_paths[0];
        assert_eq!(extent_path.state, expected_state);
        let extent_sink = result
            .evidence
            .iter()
            .find(|item| item.id == extent_path.sink_evidence_id)
            .expect("loaded-memory extent sink");
        assert_eq!(extent_sink.location.start.line, expected_extent_sink_line);
    }
}
