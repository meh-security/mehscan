use std::path::PathBuf;

use mehscan_core::SecurityPathState;

fn corpus(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../mehscan-internal/corpus-cache/apps/c-cpp")
        .join(version)
        .join("libfreerdp/codec/nsc.c")
}

#[test]
#[ignore = "requires the optional pinned FreeRDP vulnerable/fixed corpus pair"]
fn optional_freerdp_pair_tracks_cve_2026_31806_region_contract() {
    for (version, expected_state, expected_line) in [
        ("freerdp-3.23.0-vulnerable", SecurityPathState::Unknown, 531),
        ("freerdp-3.24.0-fixed", SecurityPathState::Protected, 538),
    ] {
        let target = corpus(version);
        assert!(
            target.is_file(),
            "optional corpus is missing: {}",
            target.display()
        );
        let result = mehscan_engine::scan_path(&target).expect("FreeRDP target should scan");
        let paths = result
            .security_paths
            .iter()
            .filter(|path| {
                path.provenance.engine == "mehscan c-family destination-region relationship 1"
            })
            .collect::<Vec<_>>();
        assert_eq!(
            paths.len(),
            1,
            "unexpected relationship count for {version}"
        );
        assert_eq!(paths[0].state, expected_state);
        let sink = result
            .evidence
            .iter()
            .find(|item| item.id == paths[0].sink_evidence_id)
            .expect("relationship sink");
        assert_eq!(sink.location.start.line, expected_line);
    }
}
