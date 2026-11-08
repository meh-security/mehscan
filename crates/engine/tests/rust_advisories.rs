mod support;
use std::{fs, path::PathBuf};
struct Fixture {
    root: PathBuf,
    db: PathBuf,
}
impl Fixture {
    fn new(version: &str, source: Option<&str>) -> Self {
        let root = support::temp_dir("offline-advisory-matching");
        let db = root.join("database");
        fs::create_dir_all(db.join("crates/sample-crate")).unwrap();
        let source = source
            .map(|s| format!("source={s:?}\n"))
            .unwrap_or_default();
        fs::write(
            root.join("Cargo.lock"),
            format!("version=3\n[[package]]\nname=\"sample-crate\"\nversion={version:?}\n{source}"),
        )
        .unwrap();
        Self { root, db }
    }
    fn advisory(&self, id: &str, metadata: &str, versions: &str) {
        fs::write(self.db.join("crates/sample-crate").join(format!("{id}.md")),format!("```toml\n[advisory]\nid={id:?}\npackage=\"sample-crate\"\n{metadata}\n[versions]\n{versions}\n```\n# Example advisory\n")).unwrap();
    }
    fn report(&self, include: bool) -> mehscan_engine::rust_advisories::RustAdvisoryReport {
        mehscan_engine::rust_advisories::inspect(&self.root, &self.db, include).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";
#[test]
fn version_ranges_preserve_patched_unaffected_and_applicability() {
    for (version, count) in [("1.0.0", 1), ("1.1.0", 0), ("0.8.0", 0)] {
        let f = Fixture::new(version, Some(REGISTRY));
        f.advisory(
            "RUSTSEC-2099-0001",
            "aliases=[\"CVE-2099-0001\"]",
            "patched=[\">= 1.1.0\"]\nunaffected=[\"< 0.9.0\"]",
        );
        let r = f.report(true);
        assert!(r.version_matching_complete);
        assert_eq!(r.findings.len(), count);
        assert_eq!(r.database_files_sha256.len(), 1);
        if count == 1 {
            assert_eq!(
                r.findings[0].assessment,
                "version_match_requires_applicability_review"
            );
            assert_eq!(r.findings[0].aliases, ["CVE-2099-0001"]);
        }
    }
}
#[test]
fn informational_kinds_and_malicious_records_are_distinct() {
    let f = Fixture::new("1.0.0", Some(REGISTRY));
    for (id, kind) in [
        ("RUSTSEC-2099-0001", "unsound"),
        ("RUSTSEC-2099-0002", "unmaintained"),
        ("RUSTSEC-2099-0003", "notice"),
    ] {
        f.advisory(id, &format!("informational={kind:?}"), "patched=[]");
    }
    f.advisory(
        "RUSTSEC-2099-0004",
        "categories=[\"malicious\"]",
        "patched=[]",
    );
    f.advisory(
        "RUSTSEC-2099-0005",
        "withdrawn=\"2099-01-01\"",
        "patched=[]",
    );
    let r = f.report(true);
    assert_eq!(
        r.findings
            .iter()
            .map(|r| r.kind.as_str())
            .collect::<Vec<_>>(),
        ["unsound", "unmaintained", "notice", "malicious"]
    );
    let r = f.report(false);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].kind, "malicious");
}
#[test]
fn local_git_and_alternative_registry_packages_are_not_name_matched() {
    for source in [
        None,
        Some("git+https://example.invalid/sample#abc"),
        Some("registry+https://example.invalid/index"),
    ] {
        let f = Fixture::new("1.0.0", source);
        f.advisory("RUSTSEC-2099-0001", "", "patched=[]");
        let r = f.report(true);
        assert!(r.findings.is_empty());
        assert_eq!(r.excluded_packages.len(), 1);
    }
}
#[test]
fn malformed_records_and_prereleases_never_produce_a_complete_clean_result() {
    let f = Fixture::new("1.0.0-alpha.1", Some(REGISTRY));
    f.advisory("RUSTSEC-2099-0001", "", "patched=[]");
    let r = f.report(true);
    assert!(!r.version_matching_complete);
    assert!(r.diagnostics[0].contains("prerelease"));
    let f = Fixture::new("1.0.0", Some(REGISTRY));
    f.advisory("RUSTSEC-2099-0001", "", "patched=[\"not a range\"]");
    let r = f.report(true);
    assert!(!r.version_matching_complete);
    assert!(r.findings.is_empty());
    assert_eq!(r.diagnostics.len(), 1);
    f.advisory("RUSTSEC-2099-0002", "", "patched=[]");
    fs::copy(
        f.db.join("crates/sample-crate/RUSTSEC-2099-0002.md"),
        f.db.join("crates/sample-crate/duplicate.md"),
    )
    .unwrap();
    let r = f.report(true);
    assert!(!r.version_matching_complete);
    assert!(r.diagnostics.iter().any(|s| s.contains("duplicate")));
}
