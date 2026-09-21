use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, CweSupportLevel};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/phase3")
}

#[test]
fn enumerates_first_cwe_capability_set_across_priority_languages() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.evidence.len(), 36);
    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.coverage.totals.unsupported, 0);

    let expected_surfaces = BTreeMap::from([
        ("database_query".to_string(), 7),
        ("dynamic_code_execution".to_string(), 7),
        ("filesystem_read".to_string(), 7),
        ("filesystem_write".to_string(), 8),
        ("outbound_network_request".to_string(), 7),
    ]);
    assert_eq!(result.coverage.security_surfaces, expected_surfaces);

    for capability in [
        Capability::DatabaseQuery,
        Capability::OutboundNetworkRequest,
        Capability::FilesystemRead,
        Capability::FilesystemWrite,
        Capability::DynamicCodeExecution,
    ] {
        let expected = usize::from(capability == Capability::FilesystemWrite) + 7;
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|evidence| evidence.capability == capability)
                .count(),
            expected
        );
    }

    assert!(
        result
            .evidence
            .iter()
            .all(|evidence| evidence.location.path.starts_with("positive/"))
    );
    assert!(result.evidence.iter().all(|evidence| {
        match evidence.capability {
            Capability::DatabaseQuery => evidence.captures.contains_key("query"),
            Capability::OutboundNetworkRequest => evidence.captures.contains_key("endpoint"),
            Capability::FilesystemRead | Capability::FilesystemWrite => {
                evidence.captures.contains_key("path")
            }
            Capability::DynamicCodeExecution => evidence.captures.contains_key("code"),
            _ => false,
        }
    }));

    let rules = mehscan_engine::rules::load_builtin_rules().expect("catalog should load");
    assert_eq!(
        result.coverage.producers.loaded_declarative_rules,
        rules.len()
    );

    let cwe: BTreeMap<_, _> = result
        .coverage
        .cwe
        .iter()
        .map(|coverage| (coverage.cwe.as_str(), coverage))
        .collect();
    for rule in &rules {
        for id in &rule.cwe {
            let coverage = cwe
                .get(id.as_str())
                .expect("every loaded rule CWE should have a coverage claim");
            assert_eq!(coverage.level, CweSupportLevel::Partial);
            assert!(coverage.declarative_languages.contains(&rule.language));
        }
    }
    for coverage in cwe.values() {
        let mut claimed = coverage.declarative_languages.clone();
        claimed.extend(&coverage.observed_procedural_languages);
        if coverage.language_independent {
            claimed.extend([
                mehscan_core::Language::C,
                mehscan_core::Language::Cpp,
                mehscan_core::Language::Csharp,
                mehscan_core::Language::Java,
                mehscan_core::Language::Kotlin,
                mehscan_core::Language::Javascript,
                mehscan_core::Language::Typescript,
                mehscan_core::Language::Tsx,
                mehscan_core::Language::Python,
                mehscan_core::Language::Php,
                mehscan_core::Language::Go,
                mehscan_core::Language::Rust,
            ]);
        }
        claimed.sort();
        claimed.dedup();
        assert_eq!(coverage.supported_languages, claimed);
    }
    assert!(
        !cwe.contains_key("CWE-798"),
        "disabled secret scanning must not claim language-independent coverage"
    );
}

#[test]
fn built_in_catalog_has_valid_provenance() {
    let rules = mehscan_engine::rules::load_builtin_rules().expect("catalog should validate");
    assert_eq!(rules.len(), 419);
    let invalid = rules
        .iter()
        .filter(|rule| {
            rule.provenance.note.is_empty()
                || rule.provenance.references.len() < 2
                || rule
                    .provenance
                    .references
                    .iter()
                    .any(|reference| !reference.starts_with("https://"))
        })
        .map(|rule| rule.id.as_str())
        .collect::<Vec<_>>();
    assert!(invalid.is_empty(), "invalid rule provenance: {invalid:?}");
}
