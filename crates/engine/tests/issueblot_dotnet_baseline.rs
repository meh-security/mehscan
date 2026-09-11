use std::path::{Path, PathBuf};

use mehscan_core::Capability;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/dotnet/IssueBlot.NET/src")
}

fn scan(root: &Path, project: &str) -> mehscan_core::ScanResult {
    mehscan_engine::scan_path(root.join(project)).expect("IssueBlot project should scan")
}

#[test]
#[ignore = "requires the optional local IssueBlot.NET corpus"]
fn optional_issueblot_c23_project_baselines_match_when_requested() {
    let root = corpus_root();
    assert!(
        root.join("NETWebFormsBlot/NETWebFormsBlot.csproj")
            .is_file()
    );

    let mvc = scan(&root, "NETMVCBlot");
    assert_eq!(mvc.coverage.totals.scanned, 45);
    assert_eq!(mvc.coverage.totals.parse_failed, 0);
    assert_eq!(mvc.evidence.len(), 89);
    assert_eq!(mvc.security_paths.len(), 8);
    assert_eq!(
        mvc.security_paths
            .iter()
            .filter(|path| path.capability == Capability::FileUpload)
            .count(),
        1
    );
    assert!(mvc.evidence.iter().any(|item| {
        item.rule_id == "csharp-mvc-request-validation-disabled"
            && item.location.path == "Controllers/HomeController.cs"
    }));

    let webforms = scan(&root, "NETWebFormsBlot");
    assert_eq!(webforms.coverage.totals.scanned, 50);
    assert_eq!(webforms.coverage.totals.parse_failed, 0);
    assert_eq!(webforms.evidence.len(), 95);
    assert_eq!(webforms.security_paths.len(), 13);
    assert_eq!(
        webforms
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::HtmlOutput)
            .count(),
        10
    );
    assert_eq!(
        webforms
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::FileUpload)
            .count(),
        1
    );
    assert_eq!(
        webforms
            .evidence
            .iter()
            .filter(|item| item.rule_id == "csharp-webforms-inline-request-source")
            .count(),
        8
    );

    let standalone = scan(&root, "NETStandaloneBlot");
    assert_eq!(standalone.coverage.totals.scanned, 95);
    assert_eq!(standalone.coverage.totals.parse_failed, 0);
    assert_eq!(standalone.evidence.len(), 110);
    assert_eq!(standalone.security_paths.len(), 24);
    assert_eq!(
        standalone
            .evidence
            .iter()
            .filter(|item| item.rule_id == "csharp-console-readline-source")
            .count(),
        25
    );
    assert_eq!(
        standalone
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::ProcessExecution)
            .count(),
        7
    );
    assert_eq!(
        standalone
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::DatabaseQuery)
            .count(),
        9
    );
    assert_eq!(
        standalone
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::FilesystemRead)
            .count(),
        7
    );
    assert_eq!(
        standalone
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::DynamicCodeExecution)
            .count(),
        1
    );
}
