use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{SymbolConfidence, SymbolResolutionMethod};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/aliases")
}

fn rust_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/rust-aliases")
}

#[test]
fn resolves_import_aliases_and_rejects_shadowing_ambiguity() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("alias fixture should scan");
    assert_eq!(result.coverage.totals.scanned, 10);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert!(
        result
            .evidence
            .iter()
            .all(|item| item.symbol_resolution.is_some())
    );

    let mut methods = BTreeMap::new();
    for evidence in &result.evidence {
        let resolution = evidence.symbol_resolution.as_ref().expect("checked above");
        *methods.entry(resolution.method).or_insert(0) += 1;
    }
    assert_eq!(methods.get(&SymbolResolutionMethod::Alias), Some(&11));
    assert_eq!(methods.get(&SymbolResolutionMethod::StaticImport), Some(&2));
    assert_eq!(
        methods.get(&SymbolResolutionMethod::ImportedNamespace),
        Some(&2)
    );
    assert_eq!(
        methods.get(&SymbolResolutionMethod::FullyQualified),
        Some(&1)
    );

    assert!(
        result
            .evidence
            .iter()
            .all(|item| !item.location.path.ends_with("Shadowed.cs")),
        "shadowed ambiguous call must not become framework evidence"
    );

    let global_alias = result
        .evidence
        .iter()
        .find(|item| item.location.path.ends_with("GlobalAliasUse.cs"))
        .expect("global alias should resolve across files");
    let resolution = global_alias
        .symbol_resolution
        .as_ref()
        .expect("resolved alias");
    assert_eq!(resolution.method, SymbolResolutionMethod::Alias);
    assert_eq!(resolution.confidence, SymbolConfidence::High);

    for shadowed_symbol in ["ShadowedAlias", "shadowed", "Shadowed"] {
        assert!(
            result
                .evidence
                .iter()
                .all(|item| item.enclosing_symbol.as_deref() != Some(shadowed_symbol)),
            "a parameter that shadows an import alias must not resolve as framework evidence"
        );
    }
    assert_eq!(result.evidence.len(), 16);

    let rust =
        mehscan_engine::scan_path(rust_fixture_root()).expect("Rust alias fixture should scan");
    assert_eq!(rust.coverage.totals.scanned, 1);
    assert_eq!(rust.coverage.totals.parse_failed, 0);
    assert_eq!(rust.evidence.len(), 1);
    assert_eq!(
        rust.evidence[0].enclosing_symbol.as_deref(),
        Some("rust_alias_case")
    );
    assert!(rust.evidence[0].symbol_resolution.is_none());
}
