use mehscan_core::{Capability, Language};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-native")
}

#[test]
fn kotlin_jvm_boundaries_and_scripts_preserve_captures() {
    let result = mehscan_engine::scan_path(root()).unwrap();
    assert_eq!(result.coverage.languages[&Language::Kotlin].scanned, 4);
    let native = result
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("kotlin-"))
        .collect::<Vec<_>>();
    assert_eq!(native.len(), 8);
    let rules = mehscan_engine::rules::load_builtin_rules().unwrap();
    let declared = rules
        .iter()
        .filter(|r| r.language == Language::Kotlin)
        .map(|r| r.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let exercised = native
        .iter()
        .map(|e| e.rule_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        declared, exercised,
        "Every Kotlin rule needs an executable fixture"
    );
    for cwe in ["CWE-78", "CWE-22", "CWE-327", "CWE-918"] {
        assert!(
            result
                .coverage
                .cwe
                .iter()
                .find(|item| item.cwe == cwe)
                .unwrap()
                .supported_languages
                .contains(&Language::Kotlin)
        );
    }
    let command = native
        .iter()
        .find(|e| e.rule_id == "kotlin-runtime-exec")
        .unwrap();
    assert_eq!(command.captures["command"].text, "command");
    assert_eq!(command.enclosing_symbol.as_deref(), Some("boundaries"));
    assert!(
        native
            .iter()
            .any(|e| e.capability == Capability::CryptographicHash
                && e.location.path.ends_with("script.kts"))
    );
    assert!(
        native
            .iter()
            .all(|e| !e.location.path.ends_with("inert.kt")
                && !e.location.path.ends_with("shadow.kt"))
    );
    assert!(result.security_paths.is_empty());
}

#[test]
fn kotlin_outline_and_test_policy_are_available() {
    let outline = mehscan_engine::investigation::get_file_outline(&root(), "app.kt").unwrap();
    assert_eq!(outline.results.language, Language::Kotlin);
    assert!(
        outline
            .results
            .symbols
            .iter()
            .any(|s| s.name == "boundaries")
    );
    let result = mehscan_engine::scan_path_with_options(
        root(),
        mehscan_engine::ScanOptions {
            include_tests: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.coverage.languages[&Language::Kotlin].scanned, 6);
}
