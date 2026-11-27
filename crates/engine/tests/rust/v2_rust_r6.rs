use mehscan_core::Capability;
use std::path::PathBuf;

#[test]
fn drops_generic_safety_syntax_and_preserves_build_time_execution() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/v2-rust-r6");
    for include_tests in [false, true] {
        let result = mehscan_engine::scan_path_with_options(
            &root,
            mehscan_engine::ScanOptions {
                include_tests,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.coverage.totals.parse_failed, 0);
        assert!(!result.evidence.iter().any(|item| matches!(
            item.rule_id.as_str(),
            "rust-unsafe-boundary" | "rust-native-interop-boundary" | "rust-file-log-write"
        )));
        let build = result
            .evidence
            .iter()
            .find(|item| item.capability == Capability::ProcessExecution)
            .expect("actual build execution must survive the syntax-rule removal");
        assert!(build.tags.iter().any(|tag| tag == "build-script"));
        assert!(build.tags.iter().any(|tag| tag == "build-time-execution"));
    }
}
