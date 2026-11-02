use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-rust-scope-{name}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
    fn write(&self, path: &str, source: &str) {
        fs::write(self.0.join(path), source).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn rust_test_items_and_filenames_are_excluded_while_unknown_production_cfg_is_kept() {
    let fixture = Fixture::new("items");
    let source = r#"
pub fn production(path: &str) { std::fs::write(path, b"prod"); }
#[cfg(test)]
#[allow(dead_code)]
mod suite {
    fn inline_test(path: &str) { std::fs::write(path, b"fixture"); }
}
#[test]
fn unit_test() { std::fs::write("fixture", b"test"); }
#[cfg(all(test, feature = "extra"))]
fn conjunction_test() { std::fs::write("fixture", b"test"); }
#[cfg(any(test, feature = "server"))]
fn production_feature(path: &str) { std::fs::write(path, b"prod"); }
#[cfg(not(test))]
fn production_non_test(path: &str) { std::fs::write(path, b"prod"); }
pub fn production_after(path: &str) { std::fs::write(path, b"prod"); }
"#;
    fixture.write("module.rs", source);
    for name in [
        "tests.rs",
        "test.rs",
        "model_tests.rs",
        "model_test.rs",
        "tests_api.rs",
        "contest.rs",
    ] {
        fixture.write(name, "fn sample(p: &str) { std::fs::write(p, b\"data\"); }");
    }
    let default = mehscan_engine::scan_path(&fixture.0).unwrap();
    let writes: Vec<_> = default
        .evidence
        .iter()
        .filter(|e| e.rule_id == "rust-filesystem-write")
        .collect();
    assert_eq!(writes.len(), 6);
    for name in [
        "production",
        "production_feature",
        "production_non_test",
        "production_after",
    ] {
        assert!(
            writes
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(name)),
            "{name}"
        );
    }
    assert!(writes.iter().all(|e| {
        !["inline_test", "unit_test", "conjunction_test"]
            .contains(&e.enclosing_symbol.as_deref().unwrap_or_default())
    }));
    for evidence in &default.evidence {
        for capture in evidence.captures.values() {
            let text = fs::read_to_string(fixture.0.join(&capture.location.path)).unwrap();
            assert_eq!(
                capture.text,
                text[capture.location.start.byte_offset..capture.location.end.byte_offset]
            );
        }
    }
    let included = mehscan_engine::scan_path_with_options(
        &fixture.0,
        mehscan_engine::ScanOptions {
            include_tests: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        included
            .evidence
            .iter()
            .filter(|e| e.rule_id == "rust-filesystem-write")
            .count(),
        13
    );
}

#[test]
fn test_only_route_markers_do_not_consume_the_default_admission_budget() {
    let fixture = Fixture::new("markers");
    fixture.write(
        "routes.rs",
        r#"
#[cfg(test)]
fn fixture_routes() {
    Router::new()
        .route("/fixture", post(update_item));
}

fn production_routes() {
    Router::new()
        .route("/live", post(update_item));
}
"#,
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|e| e.rule_id == "framework-authorization-review-marker")
            .count(),
        1
    );
    assert_eq!(inventory.marker_admission.recognized, 1);
    let included = mehscan_engine::investigation::build_review_inventory(&fixture.0, true).unwrap();
    assert_eq!(
        included
            .entries
            .iter()
            .filter(|e| e.rule_id == "framework-authorization-review-marker")
            .count(),
        2
    );
}

#[test]
fn opting_into_secrets_keeps_test_credentials_redacted() {
    let fixture = Fixture::new("secret-redaction");
    let credential_fixture = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/secrets/positive/secrets.ts"),
    )
    .unwrap();
    fixture.write("module.rs", &format!("#[cfg(test)]\nmod suite {{ /*\n{credential_fixture}\n*/ }}\nfn production(path: &str) {{ std::fs::write(path, b\"data\"); }}"));
    let mut fingerprints = Vec::new();
    for include_tests in [false, true] {
        let scan = mehscan_engine::scan_path_with_options(
            &fixture.0,
            mehscan_engine::ScanOptions {
                include_tests,
                scan_secrets: true,
                ..Default::default()
            },
        )
        .unwrap();
        let secrets: Vec<_> = scan
            .evidence
            .iter()
            .filter(|e| e.kind == mehscan_core::EvidenceKind::Secret)
            .collect();
        assert!(!secrets.is_empty());
        assert!(
            secrets
                .iter()
                .all(|e| e.captures["secret"].text == "[REDACTED]")
        );
        fingerprints.push(
            secrets
                .iter()
                .map(|e| e.context.secret.as_ref().unwrap().fingerprint.clone())
                .collect::<std::collections::BTreeSet<_>>(),
        );
    }
    assert_eq!(fingerprints[0], fingerprints[1]);
}
