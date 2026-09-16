use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::{Capability, FileStatus};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/file-policy")
}

#[test]
fn ignores_secret_only_text_when_secret_scanning_is_disabled() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.discovered, 2);
    assert_eq!(result.coverage.totals.scanned, 1);
    assert_eq!(result.coverage.totals.secret_scanned, 0);
    assert_eq!(result.coverage.ignored_subtrees, ["dist/"]);

    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.capability == Capability::HttpRequestData)
            .count(),
        1,
        "test and build output request lookalikes must not be SAST evidence"
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.capability == Capability::CredentialMaterial)
            .count(),
        0,
        "secret observations are disabled by default"
    );
    let test_file = result
        .coverage
        .files
        .iter()
        .find(|file| file.path == "unit/login.spec.ts")
        .expect("test source should be covered explicitly");
    assert_eq!(test_file.status, FileStatus::Ignored);
    assert!(
        test_file
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("secret scanning disabled"))
    );
}

#[test]
fn include_tests_promotes_excluded_supported_sources_into_sast() {
    let result = mehscan_engine::scan_path_with_options(
        fixture_root(),
        mehscan_engine::ScanOptions {
            include_tests: true,
            jobs: Some(2),
            scan_secrets: false,
            impact_scope: None,
        },
    )
    .expect("fixture should scan with tests");

    assert_eq!(result.coverage.totals.discovered, 2);
    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.secret_scanned, 0);
    assert_eq!(result.coverage.ignored_subtrees, ["dist/"]);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.capability == Capability::HttpRequestData)
            .count(),
        2
    );
    let test_file = result
        .coverage
        .files
        .iter()
        .find(|file| file.path == "unit/login.spec.ts")
        .expect("test source should be covered explicitly");
    assert_eq!(test_file.status, FileStatus::Scanned);
}

#[test]
fn generated_frontend_content_is_secret_only_unless_explicitly_included() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-generated-frontend-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("temporary fixture directory");
    let generated = format!(
        "const endpoint = request.query.url; fetch(endpoint); /*{}*/\n//# sourceMappingURL=compiled.js.map\n",
        "x".repeat(70 * 1024)
    );
    fs::write(root.join("compiled.js"), generated).expect("generated fixture source");

    let default = mehscan_engine::scan_path(&root).expect("default scan should run");
    assert_eq!(default.coverage.totals.discovered, 1);
    assert_eq!(default.coverage.totals.scanned, 0);
    assert_eq!(default.coverage.totals.ignored, 1);
    assert!(
        default.coverage.files[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("generated or bundled frontend"))
    );

    let secret_only = mehscan_engine::scan_path_with_options(
        &root,
        mehscan_engine::ScanOptions {
            include_tests: false,
            jobs: Some(1),
            scan_secrets: true,
            impact_scope: None,
        },
    )
    .expect("generated source should retain secret scanning");
    assert_eq!(secret_only.coverage.totals.scanned, 0);
    assert_eq!(secret_only.coverage.totals.secret_scanned, 1);
    assert_eq!(
        secret_only.coverage.files[0].status,
        FileStatus::SecretScanned
    );

    let complete = mehscan_engine::scan_path_with_options(
        &root,
        mehscan_engine::ScanOptions {
            include_tests: true,
            jobs: Some(1),
            scan_secrets: false,
            impact_scope: None,
        },
    )
    .expect("explicit complete scan should run");
    assert_eq!(complete.coverage.totals.scanned, 1);
    assert_eq!(complete.coverage.totals.ignored, 0);
    assert_eq!(complete.coverage.files[0].status, FileStatus::Scanned);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn exact_unit_test_directories_are_excluded_without_hiding_lookalikes() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-unit-test-policy-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("apps/unit_tests")).expect("unit-test fixture directory");
    fs::create_dir_all(root.join("apps/unitary")).expect("production fixture directory");
    fs::write(
        root.join("apps/unit_tests/xmlsec_unit_tests.c"),
        "int unit_test_helper(void) { return 0; }\n",
    )
    .expect("unit-test fixture source");
    fs::write(
        root.join("apps/unitary/parser.c"),
        "int production_parser(void) { return 0; }\n",
    )
    .expect("production fixture source");

    let default = mehscan_engine::scan_path(&root).expect("default scan should run");
    assert_eq!(default.coverage.totals.scanned, 1);
    assert_eq!(default.coverage.totals.ignored, 1);
    assert_eq!(
        default
            .coverage
            .files
            .iter()
            .find(|file| file.path == "apps/unit_tests/xmlsec_unit_tests.c")
            .expect("unit-test path should be covered")
            .status,
        FileStatus::Ignored
    );
    assert_eq!(
        default
            .coverage
            .files
            .iter()
            .find(|file| file.path == "apps/unitary/parser.c")
            .expect("production lookalike should be covered")
            .status,
        FileStatus::Scanned
    );

    let complete = mehscan_engine::scan_path_with_options(
        &root,
        mehscan_engine::ScanOptions {
            include_tests: true,
            jobs: Some(1),
            scan_secrets: false,
            impact_scope: None,
        },
    )
    .expect("explicit test scan should run");
    assert_eq!(complete.coverage.totals.scanned, 2);
    fs::remove_dir_all(&root).expect("remove unit-test policy fixture");
}
