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

    let cwe: BTreeMap<_, _> = result
        .coverage
        .cwe
        .iter()
        .map(|coverage| (coverage.cwe.as_str(), coverage))
        .collect();
    assert_eq!(cwe.len(), 68);
    for id in ["CWE-20", "CWE-22", "CWE-78", "CWE-89", "CWE-798", "CWE-918"] {
        let coverage = cwe.get(id).expect("CWE coverage should be declared");
        assert_eq!(coverage.level, CweSupportLevel::Partial);
        assert_eq!(
            coverage.supported_languages.len(),
            if matches!(
                id,
                "CWE-20" | "CWE-22" | "CWE-78" | "CWE-89" | "CWE-798" | "CWE-918"
            ) {
                12
            } else {
                11
            }
        );
    }
    for id in ["CWE-79", "CWE-502", "CWE-601"] {
        let coverage = cwe.get(id).expect("CWE coverage should be declared");
        assert_eq!(coverage.level, CweSupportLevel::Partial);
        assert_eq!(coverage.supported_languages.len(), 10);
    }
    for id in [
        "CWE-94", "CWE-306", "CWE-434", "CWE-614", "CWE-862", "CWE-1004",
    ] {
        let coverage = cwe.get(id).expect("CWE coverage should be declared");
        assert_eq!(coverage.level, CweSupportLevel::Partial);
        assert_eq!(
            coverage.supported_languages.len(),
            if matches!(id, "CWE-94" | "CWE-434") {
                8
            } else {
                7
            }
        );
    }
    assert_eq!(cwe["CWE-327"].supported_languages.len(), 11);
    assert_eq!(cwe["CWE-295"].supported_languages.len(), 10);
    for id in ["CWE-1275", "CWE-345"] {
        let coverage = cwe.get(id).expect("Node CWE coverage should be declared");
        assert_eq!(coverage.level, CweSupportLevel::Partial);
        assert_eq!(coverage.supported_languages.len(), 3);
    }
    assert_eq!(cwe["CWE-321"].supported_languages.len(), 5);
    assert_eq!(cwe["CWE-640"].supported_languages.len(), 4);
    assert_eq!(
        cwe["CWE-829"].supported_languages,
        [mehscan_core::Language::Csharp]
    );
    assert!(
        cwe["CWE-916"]
            .supported_languages
            .contains(&mehscan_core::Language::Csharp)
    );
    assert_eq!(
        cwe["CWE-611"].supported_languages,
        [
            mehscan_core::Language::C,
            mehscan_core::Language::Cpp,
            mehscan_core::Language::Csharp,
            mehscan_core::Language::Java,
            mehscan_core::Language::Kotlin,
            mehscan_core::Language::Javascript,
            mehscan_core::Language::Typescript,
            mehscan_core::Language::Tsx,
            mehscan_core::Language::Python,
        ]
    );
    for id in ["CWE-307", "CWE-347"] {
        let coverage = cwe
            .get(id)
            .expect("identity CWE coverage should be declared");
        assert_eq!(coverage.level, CweSupportLevel::Partial);
        assert_eq!(coverage.supported_languages.len(), 6);
    }
    assert_eq!(cwe["CWE-613"].supported_languages.len(), 5);
    assert_eq!(
        cwe["CWE-319"].supported_languages,
        [
            mehscan_core::Language::Csharp,
            mehscan_core::Language::Java,
            mehscan_core::Language::Go,
        ],
        "programmatic transport coverage should represent all implemented stacks"
    );
    assert_eq!(cwe["CWE-352"].supported_languages.len(), 4);
    assert_eq!(cwe["CWE-942"].supported_languages.len(), 5);
    let resource_access = cwe
        .get("CWE-639")
        .expect("CWE-639 coverage should be declared");
    assert_eq!(resource_access.level, CweSupportLevel::Partial);
    assert_eq!(resource_access.supported_languages.len(), 6);
    let semantic_coverage = cwe
        .get("CWE-330")
        .expect("semantic CWE coverage should be declared");
    assert_eq!(semantic_coverage.level, CweSupportLevel::Partial);
    assert_eq!(
        semantic_coverage.supported_languages,
        [
            mehscan_core::Language::Csharp,
            mehscan_core::Language::Java,
            mehscan_core::Language::Javascript,
            mehscan_core::Language::Typescript,
            mehscan_core::Language::Tsx,
        ]
    );
    assert_eq!(cwe["CWE-915"].supported_languages.len(), 3);
    assert_eq!(cwe["CWE-532"].supported_languages.len(), 4);
    for id in [
        "CWE-170", "CWE-190", "CWE-195", "CWE-367", "CWE-369", "CWE-401", "CWE-404", "CWE-416",
        "CWE-562", "CWE-680", "CWE-681", "CWE-754", "CWE-755", "CWE-772", "CWE-825", "CWE-1284",
    ] {
        assert_eq!(
            cwe[id].supported_languages,
            [mehscan_core::Language::C, mehscan_core::Language::Cpp]
        );
    }
    assert_eq!(
        cwe["CWE-762"].supported_languages,
        [mehscan_core::Language::Cpp]
    );
    for id in [
        "CWE-312", "CWE-400", "CWE-489", "CWE-598", "CWE-693", "CWE-943",
    ] {
        assert_eq!(cwe[id].supported_languages, [mehscan_core::Language::Go]);
    }
    for id in ["CWE-59", "CWE-732"] {
        assert_eq!(
            cwe[id].supported_languages,
            [
                mehscan_core::Language::C,
                mehscan_core::Language::Cpp,
                mehscan_core::Language::Go,
            ]
        );
    }
    assert_eq!(
        cwe["CWE-476"].supported_languages,
        [
            mehscan_core::Language::C,
            mehscan_core::Language::Cpp,
            mehscan_core::Language::Go,
        ]
    );
    let ldap = cwe
        .get("CWE-90")
        .expect("CWE-90 coverage should be declared");
    assert_eq!(ldap.level, CweSupportLevel::Partial);
    assert_eq!(
        ldap.supported_languages,
        [mehscan_core::Language::Csharp, mehscan_core::Language::Go]
    );
}

#[test]
fn built_in_catalog_has_valid_provenance() {
    let rules = mehscan_engine::rules::load_builtin_rules().expect("catalog should validate");
    assert_eq!(rules.len(), 346);
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
