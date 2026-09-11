use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::{Capability, EvidenceFilter, EvidenceKind, FileStatus};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/secret-files")
}

fn scan_with_secrets(root: impl AsRef<std::path::Path>) -> mehscan_core::ScanResult {
    mehscan_engine::scan_path_with_options(
        root,
        mehscan_engine::ScanOptions {
            scan_secrets: true,
            ..Default::default()
        },
    )
    .expect("fixture should scan")
}

#[test]
fn scans_configuration_text_and_applies_repository_allowlists() {
    let result = scan_with_secrets(fixture_root());

    assert_eq!(result.schema_version, "2.1");
    assert_eq!(result.coverage.totals.discovered, 10);
    assert_eq!(result.coverage.totals.scanned, 0);
    assert_eq!(result.coverage.totals.secret_scanned, 9);
    assert_eq!(result.coverage.totals.secret_skipped, 0);
    assert_eq!(result.coverage.totals.secret_suppressed, 3);
    assert_eq!(result.coverage.totals.ignored, 1);
    assert_eq!(result.evidence.len(), 5);
    assert!(
        result
            .evidence
            .iter()
            .all(|evidence| evidence.location.path.starts_with("positive/"))
    );
    assert!(result.evidence.iter().all(|evidence| {
        evidence.kind == EvidenceKind::Secret
            && evidence.capability == Capability::CredentialMaterial
            && evidence.captures["secret"].text == "[REDACTED]"
    }));
    assert!(
        result
            .coverage
            .cwe
            .iter()
            .find(|coverage| coverage.cwe == "CWE-798")
            .expect("CWE-798 coverage")
            .language_independent
    );
    assert_eq!(
        result
            .coverage
            .files
            .iter()
            .filter(|file| file.status == FileStatus::SecretScanned)
            .count(),
        9
    );
    assert!(
        result
            .coverage
            .files
            .iter()
            .all(|file| { file.status != FileStatus::SecretScanned || file.language.is_none() })
    );
}

#[test]
fn default_investigation_omits_disabled_secret_evidence() {
    let job = mehscan_engine::investigation::build_investigation_job(
        &fixture_root(),
        EvidenceFilter {
            kind: Some(EvidenceKind::Secret),
            capability: Some(Capability::CredentialMaterial),
            language: None,
            path: None,
        },
        Some(1),
        Some(20),
    )
    .expect("disabled secret investigation should build");

    assert_eq!(job.schema_version, "2.1");
    assert!(job.units.is_empty());

    let outline_error = mehscan_engine::investigation::get_file_outline(
        &fixture_root(),
        "positive/config/app.yaml",
    )
    .expect_err("text-only files do not have AST outlines");
    assert!(outline_error.to_string().contains("text-only"));

    let source = mehscan_engine::investigation::get_source(
        &fixture_root(),
        "positive/config/app.yaml",
        1,
        2,
    )
    .expect("explicit source retrieval remains available");
    assert!(source.results.text.contains("ghp_"));
}

#[test]
fn skips_binary_and_oversized_text_and_reports_invalid_allowlist_lines() {
    let temporary = TemporaryFixture::new();
    fs::write(
        temporary.path.join("valid.env"),
        b"DATABASE_PASSWORD=Q8mR4vN7xT2kW9sY6pL3\n",
    )
    .expect("valid fixture");
    fs::write(
        temporary.path.join("binary.env"),
        b"API_KEY=ghp_0123456789abcdefghijklmnopqrstuvwxyz\0binary",
    )
    .expect("binary fixture");
    fs::write(
        temporary.path.join("oversized.txt"),
        vec![b'a'; 2 * 1024 * 1024 + 1],
    )
    .expect("oversized fixture");
    fs::write(
        temporary.path.join(".mehscan-secrets-allowlist"),
        b"path=../outside\nunknown=value\n",
    )
    .expect("allowlist fixture");

    let result = scan_with_secrets(&temporary.path);
    assert_eq!(result.evidence.len(), 1, "invalid entries must fail open");
    assert_eq!(result.coverage.totals.discovered, 4);
    assert_eq!(result.coverage.totals.secret_scanned, 1);
    assert_eq!(result.coverage.totals.secret_skipped, 2);
    assert_eq!(result.coverage.totals.ignored, 1);
    assert_eq!(result.diagnostics.len(), 2);
    assert!(result.coverage.files.iter().any(|file| {
        file.path == "binary.env"
            && file.status == FileStatus::SecretSkipped
            && file.reason.as_deref() == Some("binary content detected")
    }));
    assert!(result.coverage.files.iter().any(|file| {
        file.path == "oversized.txt"
            && file.status == FileStatus::SecretSkipped
            && file
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("size limit exceeded"))
    }));
}

struct TemporaryFixture {
    path: PathBuf,
}

impl TemporaryFixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mehscan-secret-files-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("temporary fixture directory");
        Self { path }
    }
}

impl Drop for TemporaryFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
