//! Opt-in native backend contract tests, using real target reference assemblies.
use mehscan_core::{Capability, OperandFactKind};
use mehscan_engine::{csharp_semantic, investigation};
use serde_json::json;
use std::path::{Path, PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-roslyn-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        for file in ["App.cs", "Helpers.cs"] {
            let original = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/roslyn-semantic")
                .join(file);
            std::fs::copy(original, root.join(file)).unwrap();
        }
        Self(root)
    }
    fn context(&self, label: &str, target: &str, language: &str, refs: &Path) -> PathBuf {
        let path = self.0.join(format!("{label}.json"));
        std::fs::write(&path, serde_json::to_vec(&json!({"projects": [{
            "id": label, "target_framework": target, "language_version": language,
            "sources": ["App.cs", "Helpers.cs"], "references": [],
            "reference_directories": [refs], "defines": [], "nullable": false, "allow_unsafe": false
        }]})).unwrap()).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn env_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("Set {name}"))
}

#[test]
#[ignore = "requires built Roslyn helper and real .NET 8 / Framework 4.8 reference packs"]
fn native_frameworks_preserve_ids_and_expose_exact_symbols_and_boundaries() {
    let fixture = Fixture::new("profiles");
    let backend = env_path("MEHSCAN_ROSLYN_BACKEND");
    let baseline = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(csharp_semantic::queries(&baseline).len(), 4);
    for (label, target, language, env, assembly) in [
        (
            "modern",
            "net8.0",
            "12.0",
            "MEHSCAN_ROSLYN_NET8_REFS",
            "System.Data.Common, Version=8.0.0.0",
        ),
        (
            "framework",
            "net48",
            "7.3",
            "MEHSCAN_ROSLYN_NET48_REFS",
            "System.Data, Version=4.0.0.0",
        ),
    ] {
        let context = fixture.context(label, target, language, &env_path(env));
        let snapshot = csharp_semantic::collect(&fixture.0, &context, &backend, &baseline).unwrap();
        assert_eq!(snapshot.observations.len(), 4);
        assert!(snapshot.diagnostics.iter().any(|d| d["code"] == "CS0103"));
        let mut enriched = baseline.clone();
        csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut enriched).unwrap();
        for (before, after) in baseline.evidence.iter().zip(&enriched.evidence) {
            assert_eq!(before.id, after.id);
            assert_eq!(before.captures, after.captures);
            assert_eq!(before.tags, after.tags);
            assert_eq!(before.symbol_resolution, after.symbol_resolution);
        }
        assert_eq!(baseline.security_paths, enriched.security_paths);
        assert_eq!(baseline.coverage, enriched.coverage);
        let sink = |name: &str| {
            enriched
                .evidence
                .iter()
                .find(|e| {
                    e.capability == Capability::DatabaseQuery
                        && e.enclosing_symbol.as_deref() == Some(name)
                })
                .unwrap()
        };
        let raw = sink("Raw");
        assert!(
            raw.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::SemanticIdentity
                    && f.value.contains(assembly)
                    && f.value.contains(target))
        );
        assert!(
            raw.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::SemanticDefinition
                    && f.location.path == "Helpers.cs")
        );
        // Unicode preceding the query must not skew the imported byte ranges.
        assert!(
            raw.context
                .operand_facts
                .iter()
                .filter(|f| f.kind == OperandFactKind::SemanticIdentity)
                .all(|f| f
                    .remaining_checks
                    .iter()
                    .any(|c| c == "partial_semantic_context"))
        );
        let changed = sink("Changed");
        assert!(
            changed
                .context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::OperandBoundary
                    && f.value.contains("Intervening reference")
                    && f.location.start.line == 26)
        );
        let missing = sink("Missing");
        assert!(missing.context.operand_facts.iter().any(|f| {
            f.kind == OperandFactKind::OperandBoundary
                && f.remaining_checks
                    .iter()
                    .any(|c| c == "missing_or_ambiguous_producer_implementation")
        }));
        assert!(
            !missing
                .context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::SemanticDefinition)
        );

        let snapshot_path = fixture.0.join(format!("{label}-snapshot.json"));
        std::fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let inventory = investigation::build_review_inventory_with_semantics(
            &fixture.0,
            false,
            Some((&snapshot_path, &context)),
        )
        .unwrap();
        let plain = investigation::build_review_inventory(&fixture.0, false).unwrap();
        assert_eq!(
            plain
                .entries
                .iter()
                .map(|e| &e.review_id)
                .collect::<Vec<_>>(),
            inventory
                .entries
                .iter()
                .map(|e| &e.review_id)
                .collect::<Vec<_>>()
        );
        let selected = inventory
            .entries
            .iter()
            .map(|e| e.review_id.clone())
            .collect();
        let jobs =
            investigation::build_selected_review_jobs(&fixture.0, &inventory, &selected, Some(4))
                .unwrap();
        assert!(
            serde_json::to_string(&jobs)
                .unwrap()
                .contains("semantic_definition")
        );
    }
}

#[test]
#[ignore = "requires built Roslyn helper and real .NET 8 reference pack"]
fn native_snapshot_rejects_staleness_and_withholds_conflicting_contexts() {
    let fixture = Fixture::new("staleness");
    let context = fixture.context(
        "app",
        "net8.0",
        "12.0",
        &env_path("MEHSCAN_ROSLYN_NET8_REFS"),
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let backend = env_path("MEHSCAN_ROSLYN_BACKEND");
    let snapshot = csharp_semantic::collect(&fixture.0, &context, &backend, &scan).unwrap();
    let original = std::fs::read(fixture.0.join("Helpers.cs")).unwrap();
    std::fs::write(fixture.0.join("Helpers.cs"), b"public class Changed {}").unwrap();
    let mut copy = scan.clone();
    assert!(
        csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut copy)
            .unwrap_err()
            .0
            .contains("stale")
    );
    assert_eq!(copy, scan);
    std::fs::write(fixture.0.join("Helpers.cs"), original).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&context).unwrap()).unwrap();
    document["projects"][0]["defines"] = json!(["CHANGED"]);
    std::fs::write(&context, serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(
        csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut copy)
            .unwrap_err()
            .0
            .contains("context is stale")
    );
    let mut second = document["projects"][0].clone();
    second["id"] = json!("second");
    document["projects"].as_array_mut().unwrap().push(second);
    std::fs::write(&context, serde_json::to_vec(&document).unwrap()).unwrap();
    let conflicting = csharp_semantic::collect(&fixture.0, &context, &backend, &scan).unwrap();
    csharp_semantic::enrich(&fixture.0, &context, &conflicting, &mut copy).unwrap();
    assert_eq!(scan.evidence, copy.evidence);
    assert!(
        copy.diagnostics
            .iter()
            .any(|d| d.message.contains("multiple target/project contexts"))
    );

    // Reference contents are part of the snapshot, even at the same path.
    let reference = fixture.0.join("copied-reference.dll");
    std::fs::copy(
        env_path("MEHSCAN_ROSLYN_NET8_REFS").join("System.Data.Common.dll"),
        &reference,
    )
    .unwrap();
    document["projects"] = json!([document["projects"][0].clone()]);
    document["projects"][0]["references"] = json!([reference]);
    std::fs::write(&context, serde_json::to_vec(&document).unwrap()).unwrap();
    let with_reference = csharp_semantic::collect(&fixture.0, &context, &backend, &scan).unwrap();
    std::fs::write(&reference, b"changed metadata").unwrap();
    let mut unchanged = scan.clone();
    assert!(
        csharp_semantic::enrich(&fixture.0, &context, &with_reference, &mut unchanged)
            .unwrap_err()
            .0
            .contains("reference snapshot is stale")
    );
    assert_eq!(unchanged, scan);
}

#[test]
#[ignore = "requires built Roslyn helper and real .NET 8 reference pack"]
fn native_binding_distinguishes_source_lookalikes_and_inline_producer_from_sink() {
    let fixture = Fixture::new("identity");
    let context = fixture.context(
        "lookalike",
        "net8.0",
        "12.0",
        &env_path("MEHSCAN_ROSLYN_NET8_REFS"),
    );
    // Canonical Windows roots use verbatim paths; nested root-relative paths
    // still use portable '/' separators in the scanner and snapshot.
    std::fs::create_dir(fixture.0.join("nested")).unwrap();
    std::fs::rename(
        fixture.0.join("Helpers.cs"),
        fixture.0.join("nested/Helpers.cs"),
    )
    .unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&context).unwrap()).unwrap();
    document["projects"][0]["sources"] = json!(["App.cs", "nested/Helpers.cs"]);
    std::fs::write(&context, serde_json::to_vec(&document).unwrap()).unwrap();
    let source = "using System.Data.Common;\npublic class Review { public void Inline(DbCommand command, string input) { command.CommandText = Helpers.Build(input); } }\nnamespace System.Data.Common { public class DbCommand { public string CommandText { get; set; } } }\n";
    std::fs::write(fixture.0.join("App.cs"), source).unwrap();
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert!(!csharp_semantic::queries(&scan).is_empty());
    let snapshot = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    let facts = &snapshot.observations[0].facts;
    let sink = facts
        .iter()
        .find(|f| f.role == "sink" && f.kind == OperandFactKind::SemanticIdentity)
        .unwrap();
    assert!(sink.value.contains("DbCommand.CommandText"));
    assert!(sink.value.contains("assembly=lookalike,"));
    assert!(!sink.value.contains("assembly=System.Data.Common,"));
    assert!(facts.iter().any(|f| f.role == "query"
        && f.kind == OperandFactKind::SemanticDefinition
        && f.location.path == "nested/Helpers.cs"));
}
