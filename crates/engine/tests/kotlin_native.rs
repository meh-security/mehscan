use mehscan_core::{Capability, Language};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-native")
}

#[test]
fn kotlin_jvm_boundaries_and_scripts_preserve_captures() {
    let result = mehscan_engine::scan_path(root()).unwrap();
    assert_eq!(result.coverage.languages[&Language::Kotlin].scanned, 5);
    let native = result
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("kotlin-"))
        .collect::<Vec<_>>();
    assert_eq!(native.len(), 9);
    let rules = mehscan_engine::rules::load_builtin_rules().unwrap();
    let declared = rules
        .iter()
        .filter(|r| r.language == Language::Kotlin)
        .map(|r| r.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut exercised = native
        .iter()
        .map(|e| e.rule_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for fixture in ["kotlin-quality", "kotlin-jdbc"] {
        let scan = mehscan_engine::scan_path(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures")
                .join(fixture),
        )
        .unwrap();
        exercised.extend(
            scan.evidence
                .into_iter()
                .map(|e| e.rule_id)
                .filter(|id| declared.contains(id)),
        );
    }
    assert_eq!(
        declared, exercised,
        "Every Kotlin rule needs an executable fixture"
    );
    for cwe in ["CWE-78", "CWE-22", "CWE-327", "CWE-918", "CWE-89"] {
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
    assert_eq!(result.coverage.languages[&Language::Kotlin].scanned, 7);
}

#[test]
fn kotlin_quality_app_admits_unsafe_and_safe_operations_without_verdicts() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-quality");
    let result = mehscan_engine::scan_path(fixture).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let observations = result
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("kotlin-") && e.kind == mehscan_core::EvidenceKind::Sink)
        .collect::<Vec<_>>();
    let owners = observations
        .iter()
        .filter_map(|e| e.enclosing_symbol.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        owners,
        [
            "rawQuery",
            "boundQuery",
            "boundJdbcQuery",
            "numericQuery",
            "rawJdbcQuery",
            "rawCommand",
            "fixedCommand"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(observations.len(), 7);
    assert_eq!(result.security_paths.len(), 3);
    let linked = result
        .security_paths
        .iter()
        .map(|p| {
            result
                .evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        linked,
        ["rawCommand", "rawQuery", "rawJdbcQuery"]
            .into_iter()
            .collect()
    );
}

#[test]
fn kotlin_review_constraints_and_sources_stay_with_their_owner() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-quality");
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    let encoded = serde_json::to_value(job).unwrap();
    let reviews = encoded["observation_reviews"].as_array().unwrap();
    let numeric = reviews
        .iter()
        .find(|review| review.to_string().contains("numeric_query_operand_context"))
        .unwrap();
    let text = numeric.to_string();
    assert!(text.contains("numericQuery"));
    assert!(!text.contains("fun rawCommand"));
    assert!(!text.contains("fun rawQuery"));
    assert!(!text.contains("kotlin-spring-mvc-parameter-source"));
    assert!(
        reviews
            .iter()
            .filter(|review| review.to_string().contains("numeric_query_operand_context"))
            .count()
            == 1
    );
}

#[test]
fn jdbc_paths_track_sql_text_and_leave_separately_bound_values_as_data() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-jdbc");
    let result = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let sinks = result
        .evidence
        .iter()
        .filter(|e| e.kind == mehscan_core::EvidenceKind::Sink)
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 4);
    assert_eq!(result.security_paths.len(), 2);
    let owners = result
        .security_paths
        .iter()
        .map(|p| {
            result
                .evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        owners,
        ["rawStatement", "rawPrepared"].into_iter().collect()
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    assert_eq!(jobs.total_reviews, 4);
    assert!(
        serde_json::to_string(&jobs)
            .unwrap()
            .contains("constant_query_operand_context")
    );
}
