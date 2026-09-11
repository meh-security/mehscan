use std::path::PathBuf;
use std::process::Command;

#[test]
fn reports_the_cli_package_version() {
    for argument in ["--version", "-V", "version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .arg(argument)
            .output()
            .expect("run version command");
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).expect("version is UTF-8"),
            format!("mehscan {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/v2-sql-flow")
}

fn scan(format: &str) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "scan",
            fixture_root().to_str().expect("UTF-8 fixture path"),
            "--format",
            format,
        ])
        .output()
        .expect("scan command should run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("output should be JSON")
}

#[test]
fn candidate_format_excludes_raw_observation_inventory() {
    let report = scan("candidates");

    assert_eq!(report["schema_version"], "1.0");
    assert_eq!(report["root"], ".");
    assert_eq!(report["scan_schema_version"], "2.1");
    assert_eq!(
        report["candidates"].as_array().expect("candidates").len(),
        15
    );
    assert!(report.get("evidence").is_none());
    assert!(report["candidates"][0].get("source").is_some());
    assert!(report["candidates"][0].get("sink").is_some());
}

#[test]
fn sarif_format_emits_candidates_instead_of_raw_observations() {
    let sarif = scan("sarif");

    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["properties"]["scanRoot"], ".");
    assert_eq!(sarif["runs"][0]["columnKind"], "unicodeCodePoints");
    assert_eq!(
        sarif["runs"][0]["results"]
            .as_array()
            .expect("results")
            .len(),
        15
    );
    assert_eq!(sarif["runs"][0]["results"][0]["kind"], "review");
    assert!(sarif["runs"][0].get("evidence").is_none());
    assert!(sarif["runs"][0]["results"][0]["codeFlows"].is_array());
}

#[test]
fn timings_are_machine_readable_and_do_not_change_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "scan",
            fixture_root().to_str().expect("UTF-8 fixture path"),
            "--format",
            "json",
            "--timings",
        ])
        .output()
        .expect("timed scan command should run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let scan: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should remain scan JSON");
    let profile: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("stderr should contain one profile object");
    assert_eq!(scan["schema_version"], "2.1");
    assert_eq!(scan["root"], ".");
    assert!(profile["total_microseconds"].as_u64().is_some());
    assert!(
        profile["file_analysis"]["declarative_patterns_considered"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(
        profile["file_analysis"]["declarative_patterns_skipped"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
}
