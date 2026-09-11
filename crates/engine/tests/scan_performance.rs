use std::path::PathBuf;

#[test]
#[ignore = "requires the optional local Juice Shop corpus and an optimized build"]
fn release_juice_shop_scan_stays_within_the_reviewed_budget() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("juice-shop");
    let (result, profile) =
        mehscan_engine::scan_path_profiled(root).expect("Juice Shop should scan");

    assert_eq!(result.evidence.len(), 727);
    assert_eq!(result.security_paths.len(), 45);
    assert_eq!(profile.file_analysis.files, 399);
    assert!(profile.file_analysis.declarative_patterns_considered > 0);
    assert!(
        profile.file_analysis.declarative_patterns_skipped * 100
            >= profile.file_analysis.declarative_patterns_considered * 85,
        "declarative admission ratio regressed: {profile:#?}"
    );
    assert!(
        profile.total_microseconds <= 10_000_000,
        "release scan exceeded the reviewed 10 second budget: {profile:#?}"
    );
}
