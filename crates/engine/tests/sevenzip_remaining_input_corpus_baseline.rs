use std::path::PathBuf;

use mehscan_core::SecurityPathState;

fn corpus(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../mehscan-internal/corpus-cache/apps/c-cpp")
        .join(version)
        .join("CPP/7zip/Archive/AvbHandler.cpp")
}

fn corpus_root(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../mehscan-internal/corpus-cache/apps/c-cpp")
        .join(version)
}

#[test]
#[ignore = "requires the optional pinned 7-Zip 26.00/26.01 AVB parser pair"]
fn optional_sevenzip_pair_tracks_nonwrapping_remaining_input_checks() {
    for (version, expected) in [
        (
            "7zip-26.00-vulnerable",
            vec![
                (SecurityPathState::Unknown, 411, 414),
                (SecurityPathState::Unknown, 417, 420),
                (SecurityPathState::Unknown, 423, 426),
            ],
        ),
        (
            "7zip-26.01-fixed",
            vec![(SecurityPathState::Protected, 419, 422)],
        ),
    ] {
        let target = corpus(version);
        assert!(target.is_file(), "missing corpus: {}", target.display());
        let result = mehscan_engine::scan_path(&target).expect("AVB handler should scan");
        let mut actual = result
            .security_paths
            .iter()
            .filter(|path| {
                path.provenance.engine == "mehscan c-family remaining-input relationship 1"
            })
            .map(|path| {
                let source = result
                    .evidence
                    .iter()
                    .find(|item| item.id == path.source_evidence_id)
                    .expect("source");
                let sink = result
                    .evidence
                    .iter()
                    .find(|item| item.id == path.sink_evidence_id)
                    .expect("sink");
                assert_eq!(path.cwe_candidates, ["CWE-190", "CWE-125"]);
                (
                    path.state,
                    source.location.start.line,
                    sink.location.start.line,
                )
            })
            .collect::<Vec<_>>();
        actual.sort_by_key(|item| item.1);
        assert_eq!(
            actual, expected,
            "unexpected AVB relationships for {version}"
        );
    }
}

#[test]
#[ignore = "requires full optional pinned 7-Zip 26.00/26.01 trees"]
fn optional_sevenzip_pair_has_no_unrelated_unresolved_remaining_input_paths() {
    for (version, expected_unknown, expected_protected) in
        [("7zip-26.00-vulnerable", 3, 2), ("7zip-26.01-fixed", 0, 3)]
    {
        let root = corpus_root(version);
        assert!(root.is_dir(), "missing corpus: {}", root.display());
        let result = mehscan_engine::scan_path(&root).expect("7-Zip tree should scan");
        let paths = result
            .security_paths
            .iter()
            .filter(|path| {
                path.provenance.engine == "mehscan c-family remaining-input relationship 1"
            })
            .collect::<Vec<_>>();
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.state == SecurityPathState::Unknown)
                .count(),
            expected_unknown,
            "unexpected unresolved paths in {version}"
        );
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.state == SecurityPathState::Protected)
                .count(),
            expected_protected,
            "unexpected protected controls in {version}"
        );
        assert!(paths.iter().all(|path| {
            let source = result
                .evidence
                .iter()
                .find(|item| item.id == path.source_evidence_id)
                .expect("source");
            source.location.path.ends_with("AvbHandler.cpp")
                || source.location.path.ends_with("Nsis/NsisHandler.cpp")
                || source.location.path.ends_with("Udf/UdfIn.cpp")
        }));
    }
}
