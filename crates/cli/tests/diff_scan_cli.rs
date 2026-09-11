use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::ScanResult;

#[test]
fn diff_mode_requires_a_change_source() {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(["scan", ".", "--diff-mode", "impact"])
        .output()
        .expect("run mehscan");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--diff-mode requires --changed-from or --files-from")
    );
}

#[test]
fn full_and_impact_diff_modes_have_distinct_result_scopes() {
    let root = temp_repository("modes");
    write(&root.join("lib/input.js"), "export const input = 'safe';\n");
    write(
        &root.join("routes/use-input.js"),
        "import { input } from '../lib/input.js';\neval(request.query.code);\n",
    );
    write(
        &root.join("other/noise.js"),
        "eval(request.query.unrelated);\n",
    );
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "baseline"]);
    write(
        &root.join("lib/input.js"),
        "export const input = request.query.changed;\neval(input);\n",
    );

    let full = scan(&root, &["--changed-from", "HEAD"]);
    let full_scope = full.impact_scope.as_ref().expect("full diff scope");
    assert_eq!(full_scope.strategy, "full_scan_changed_results");
    assert_eq!(full_scope.result_policy, "changed_locations");
    assert!(full_scope.full_scan);
    assert!(!full.evidence.is_empty());
    assert!(
        full.evidence
            .iter()
            .all(|item| item.location.path == "lib/input.js")
    );

    let impact = scan(&root, &["--changed-from", "HEAD", "--diff-mode", "impact"]);
    let impact_scope = impact.impact_scope.as_ref().expect("impact diff scope");
    assert_eq!(impact_scope.strategy, "changed_and_bounded_dependents");
    assert_eq!(impact_scope.result_policy, "impact_scope");
    assert!(!impact_scope.full_scan);
    assert!(
        impact_scope
            .included_files
            .iter()
            .any(|item| item.path == "routes/use-input.js" && item.reason == "direct_dependent")
    );
    assert!(
        impact
            .evidence
            .iter()
            .any(|item| item.location.path == "routes/use-input.js")
    );
    assert!(
        !impact
            .evidence
            .iter()
            .any(|item| item.location.path == "other/noise.js")
    );

    let candidates = scan_value(&root, &["--changed-from", "HEAD", "--format", "candidates"]);
    assert_eq!(
        candidates["impact_scope"]["result_policy"],
        "changed_locations"
    );
    let sarif = scan_value(&root, &["--changed-from", "HEAD", "--format", "sarif"]);
    assert_eq!(
        sarif["runs"][0]["properties"]["impactScope"]["result_policy"],
        "changed_locations"
    );
}

#[test]
fn deletion_forces_all_results_in_both_modes() {
    let root = temp_repository("deletion");
    write(&root.join("lib/removed.js"), "export const value = 1;\n");
    write(&root.join("other/noise.js"), "eval(request.query.code);\n");
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "baseline"]);
    fs::remove_file(root.join("lib/removed.js")).expect("delete tracked fixture");

    for extra in [Vec::<&str>::new(), vec!["--diff-mode", "impact"]] {
        let mut arguments = vec!["--changed-from", "HEAD"];
        arguments.extend(extra);
        let result = scan(&root, &arguments);
        let scope = result.impact_scope.as_ref().expect("deletion scope");
        assert!(scope.full_scan);
        assert_eq!(scope.result_policy, "all");
        assert!(
            result
                .evidence
                .iter()
                .any(|item| item.location.path == "other/noise.js")
        );
    }
}

fn scan(root: &Path, arguments: &[&str]) -> ScanResult {
    serde_json::from_value(scan_value_with_default_format(root, arguments))
        .expect("parse scan result")
}

fn scan_value(root: &Path, arguments: &[&str]) -> serde_json::Value {
    run_scan(root, arguments)
}

fn scan_value_with_default_format(root: &Path, arguments: &[&str]) -> serde_json::Value {
    let mut arguments = arguments.to_vec();
    arguments.extend(["--format", "json"]);
    run_scan(root, &arguments)
}

fn run_scan(root: &Path, arguments: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .arg("scan")
        .arg(root)
        .args(arguments)
        .output()
        .expect("run mehscan");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse scan JSON")
}

fn temp_repository(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-diff-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create fixture repository");
    git(&root, &["init"]);
    git(&root, &["config", "user.email", "mehscan@example.invalid"]);
    git(&root, &["config", "user.name", "Mehscan Test"]);
    root
}

fn write(path: &Path, source: &str) {
    fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
    fs::write(path, source).expect("write fixture");
}

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
}
