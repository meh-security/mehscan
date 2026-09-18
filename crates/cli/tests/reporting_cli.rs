use std::path::PathBuf;
use std::process::Command;

#[test]
fn empty_review_runs_render_all_formats_and_keep_the_manifest_fingerprint() {
    let directory =
        std::env::temp_dir().join(format!("mehscan-empty-report-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create empty run");
    let manifest_path = directory.join("manifest.json");
    let mut manifest = serde_json::json!({
        "schema_version": "1.0", "root": ".", "operation": "build_path_review_bundles",
        "job_fingerprint": "empty-run-fingerprint", "max_input_bytes": 524288,
        "max_reviews_per_bundle": 20, "review_count": 0, "bundle_count": 0, "bundles": [],
        "coverage": {"discovered": 3, "scanned": 0, "ignored": 2, "unsupported": 1, "parse_failed": 0},
        "scope": ["Original regression fixtures intentionally included; not deployed code.", "Scope label: Inherited old caption", "Project label: inherited-project"]
    });
    std::fs::write(&manifest_path, manifest.to_string()).expect("write manifest");
    for format in ["json", "sarif", "markdown"] {
        let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args([
                "report",
                "--run",
                directory.to_str().expect("run path"),
                "--format",
                format,
                "--project",
                "example-app",
                "--revision",
                "test-revision",
                "--scope-label",
                "Selected source only; not a full application assessment.",
            ])
            .output()
            .expect("render empty report");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if format == "json" {
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("JSON report");
            assert_eq!(report["scan"]["job_fingerprint"], "empty-run-fingerprint");
            assert_eq!(report["summary"]["reviewed"], 0);
            assert_eq!(report["findings"], serde_json::json!([]));
            assert_eq!(report["scan"]["coverage"], manifest["coverage"]);
            let mut expected_scope = manifest["scope"].as_array().unwrap().clone();
            expected_scope.retain(|entry| {
                !entry.as_str().unwrap().starts_with("Scope label: ")
                    && !entry.as_str().unwrap().starts_with("Project label: ")
            });
            expected_scope.extend([
                serde_json::json!(
                    "Scope label: Selected source only; not a full application assessment."
                ),
                serde_json::json!("Project label: example-app"),
                serde_json::json!("Source revision label: test-revision"),
            ]);
            assert_eq!(report["scan"]["scope"], serde_json::json!(expected_scope));
        } else if format == "sarif" {
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("SARIF report");
            assert_eq!(report["runs"][0]["results"], serde_json::json!([]));
            let scope = report["runs"][0]["properties"]["scope"].to_string();
            assert!(scope.contains("Project label: example-app"));
            assert!(scope.contains("Original regression fixtures intentionally included"));
            assert!(!scope.contains("Inherited old caption"));
            assert!(!scope.contains("inherited-project"));
        } else {
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(text.contains("3 discovered, 0 scanned, 2 ignored"));
            assert!(text.contains("Original regression fixtures intentionally included"));
            assert!(text.contains("Project label: example-app"));
            assert!(text.contains("Source revision label: test-revision"));
            assert!(text.contains("Selected source only; not a full application assessment."));
            assert!(!text.contains("Inherited old caption"));
            assert!(!text.contains("inherited-project"));
        }
    }
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-summary",
            "--run",
            directory.to_str().expect("run path"),
        ])
        .output()
        .expect("summarize empty run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).expect("summary JSON");
    assert_eq!(summary["job_fingerprint"], "empty-run-fingerprint");
    assert_eq!(summary["review_count"], 0);

    // Missing responses must never be disguised as a legitimately empty run.
    manifest["review_count"] = serde_json::json!(1);
    std::fs::write(&manifest_path, manifest.to_string()).expect("write inconsistent manifest");
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(["report", "--run", directory.to_str().expect("run path")])
        .output()
        .expect("reject inconsistent empty run");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("review manifest count"));
    std::fs::remove_dir_all(directory).expect("remove temporary run");
}

#[test]
fn bundle_manifest_retains_portable_scope_labels_and_scanned_selection() {
    let directory =
        std::env::temp_dir().join(format!("mehscan-scope-report-{}", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundles",
            fixture_root().to_str().unwrap(),
            "--output",
            directory.to_str().unwrap(),
            "--include-review-material",
            "true",
            "--project",
            "sql-fixture",
            "--revision",
            "fixture-revision",
            "--scope-label",
            "Regression fixtures; not deployed application code.",
        ])
        .output()
        .expect("generate labeled bundles");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let scope = manifest["scope"].to_string();
    assert!(scope.contains("Project label: sql-fixture"));
    assert!(scope.contains("Source revision label: fixture-revision"));
    assert!(scope.contains("Regression fixtures; not deployed application code."));
    assert!(scope.contains("Scanned source files (results apply to this selection only):"));
    assert!(!scope.contains(&fixture_root().display().to_string()));
    assert_eq!(manifest["root"], ".");
    std::fs::remove_dir_all(directory).expect("remove temporary bundles");
}

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
