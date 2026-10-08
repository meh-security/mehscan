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
#[ignore = "requires built Roslyn helper and real .NET 8 refs"]
fn awaited_and_cfg_producers_locate_exact_helpers_without_safety_claims() {
    let fixture = Fixture::new("producer-navigation");
    for file in ["App.cs", "Helpers.cs"] {
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/roslyn-producer-navigation")
                .join(file),
            fixture.0.join(file),
        )
        .unwrap();
    }
    let context = fixture.context(
        "navigation",
        "net8.0",
        "12.0",
        &env_path("MEHSCAN_ROSLYN_NET8_REFS"),
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let snapshot = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["projects"][0]["compiler_errors"],
        0
    );
    for (method, expected, forbidden) in [
        ("DirectAwait", vec!["Helpers.ResolveAsync"], None),
        ("CfgAwait", vec!["Helpers.ResolveAsync"], None),
        ("Replaced", vec!["Other.Resolve"], Some("Helpers.Resolve")),
        (
            "Alternatives",
            vec!["Helpers.Resolve", "Other.Resolve"],
            None,
        ),
        ("NestedArgument", vec![], Some("Helpers.Resolve")),
    ] {
        let anchors: Vec<_> = scan
            .evidence
            .iter()
            .filter(|e| {
                e.capability == Capability::FilesystemWrite
                    && e.enclosing_symbol.as_deref() == Some(method)
            })
            .collect();
        assert!(!anchors.is_empty(), "missing sink: {method}");
        for anchor in anchors {
            let observation = snapshot
                .observations
                .iter()
                .find(|o| o.evidence_id == anchor.id)
                .unwrap();
            let definitions: Vec<_> = observation
                .facts
                .iter()
                .filter(|f| f.kind == OperandFactKind::SemanticDefinition && f.role == "path")
                .collect();
            for name in &expected {
                let definition = definitions
                    .iter()
                    .find(|f| f.value.contains(name))
                    .unwrap_or_else(|| panic!("{method}: missing {name}: {definitions:?}"));
                assert_eq!(definition.location.path, "Helpers.cs");
                assert!(
                    definition
                        .remaining_checks
                        .iter()
                        .any(|c| c == "runtime_dispatch_and_replacement")
                );
            }
            if let Some(name) = forbidden {
                assert!(
                    !definitions.iter().any(|f| f.value.contains(name)),
                    "{method}: wrong producer"
                );
            }
            assert!(
                serde_json::to_value(observation).unwrap()["locally_complete_path_selection"]
                    == false,
                "{method}: navigation must not close unknown input"
            );
        }
    }
    // A second source project owns the stored property and its writes. Same-name
    // fields in another type are not writers to the consumed property.
    let refs = env_path("MEHSCAN_ROSLYN_NET8_REFS");
    std::fs::write(&context, serde_json::to_vec(&json!({"projects": [
        {"id":"reader", "target_framework":"net8.0", "language_version":"12.0", "sources":["App.cs"], "references":[], "reference_directories":[refs], "defines":[], "project_references":["writers"]},
        {"id":"writers", "target_framework":"net8.0", "language_version":"12.0", "sources":["Helpers.cs"], "references":[], "reference_directories":[refs], "defines":[]}
    ]})).unwrap()).unwrap();
    let snapshot = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    let selected = |method: &str| {
        let anchor = scan
            .evidence
            .iter()
            .find(|e| {
                e.capability == Capability::FilesystemWrite
                    && e.enclosing_symbol.as_deref() == Some(method)
            })
            .unwrap();
        snapshot
            .observations
            .iter()
            .find(|o| o.evidence_id == anchor.id)
            .unwrap()
    };
    let stored = selected("Stored");
    let writes: Vec<_> = stored
        .facts
        .iter()
        .filter(|f| f.role == "property_writer" && f.kind == OperandFactKind::LocalOperandOrigin)
        .collect();
    assert_eq!(writes.len(), 2, "{writes:?}");
    assert!(writes.iter().any(|f| f.value.contains("Guid.NewGuid()")));
    assert!(writes.iter().any(|f| f.value.contains("source.Key")));
    assert!(writes.iter().all(|f| {
        f.location.path == "Helpers.cs"
            && f.remaining_checks
                .iter()
                .any(|c| c == "same_resource_instance_and_persistence")
    }));
    assert!(serde_json::to_value(stored).unwrap()["locally_complete_path_selection"] == false);
    let many = selected("ManyStored");
    assert_eq!(many.facts.iter().filter(|f| f.role == "property_writer" && f.kind == OperandFactKind::LocalOperandOrigin).count(), 8);
    assert!(many.facts.iter().any(|f| {
        f.role == "property_writer"
            && f.kind == OperandFactKind::OperandBoundary
            && f.remaining_checks
                .iter()
                .any(|c| c == "remaining_property_writers")
    }));
    let snapshot_file = fixture.0.join("writer-snapshot.json");
    std::fs::write(&snapshot_file, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    investigation::build_review_inventory_with_semantics(
        &fixture.0,
        false,
        Some((&snapshot_file, &context)),
    )
    .expect("writer navigation must pass exact-source inventory validation");
}

#[test]
#[ignore = "requires real .NET and ASP.NET 8/10 refs plus Roslyn backend"]
fn html_proofs_and_shared_destinations_preserve_unsafe_and_distinct_cases() {
    let fixture = Fixture::new("output-destination");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/roslyn-output/App.cs"),
        fixture.0.join("App.cs"),
    )
    .unwrap();
    // An unrelated compiler gap must not veto a locally complete framework proof.
    std::fs::write(
        fixture.0.join("Helpers.cs"),
        "class Gap { UnknownType Missing; }",
    )
    .unwrap();
    let baseline = mehscan_engine::scan_path(&fixture.0).unwrap();
    let plain = investigation::build_review_inventory(&fixture.0, false).unwrap();
    for (target, language, refs, aspnet) in [
        (
            "net8.0",
            "12.0",
            "MEHSCAN_ROSLYN_NET8_REFS",
            "MEHSCAN_ROSLYN_ASPNET8_REFS",
        ),
        (
            "net10.0",
            "14.0",
            "MEHSCAN_ROSLYN_NET10_REFS",
            "MEHSCAN_ROSLYN_ASPNET10_REFS",
        ),
    ] {
        let context = fixture.context(target, target, language, &env_path(refs));
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&context).unwrap()).unwrap();
        json["projects"][0]["reference_directories"]
            .as_array_mut()
            .unwrap()
            .push(json!(env_path(aspnet)));
        std::fs::write(&context, serde_json::to_vec(&json).unwrap()).unwrap();
        let snapshot = csharp_semantic::collect(
            &fixture.0,
            &context,
            &env_path("MEHSCAN_ROSLYN_BACKEND"),
            &baseline,
        )
        .unwrap();
        let facts = |name: &str| {
            baseline
                .evidence
                .iter()
                .filter(|e| e.enclosing_symbol.as_deref() == Some(name))
                .flat_map(|e| {
                    snapshot
                        .observations
                        .iter()
                        .filter(move |o| o.evidence_id == e.id)
                        .flat_map(|o| &o.facts)
                })
                .collect::<Vec<_>>()
        };
        for name in [
            "Encoded",
            "Child",
            "Fragment",
            "ReadonlyHtml",
            "ReadonlyString",
            "EmptyHtml",
            "EncodedRead",
            "ImmutableHtmlRead",
        ] {
            assert!(
                facts(name)
                    .iter()
                    .any(|f| f.kind == OperandFactKind::EncodedHtmlOperand),
                "missing HTML proof: {target}/{name}: {:?}",
                facts(name)
            );
        }
        for name in ["Json", "Plain"] {
            assert!(
                facts(name)
                    .iter()
                    .any(|f| f.kind == OperandFactKind::NonHtmlResponse),
                "missing MIME proof: {target}/{name}"
            );
        }
        for name in [
            "Html",
            "Different",
            "Conditional",
            "Replaced",
            "Intervening",
            "ArgumentMutation",
        ] {
            assert!(
                !facts(name)
                    .iter()
                    .any(|f| f.kind == OperandFactKind::NonHtmlResponse),
                "unsafe MIME closure: {target}/{name}"
            );
        }
        for name in [
            "Raw",
            "SuppliedEncoder",
            "Replaced",
            "RawChild",
            "LaterRawChild",
            "AliasedChild",
            "Link",
            "Script",
            "ConstructorReplacement",
            "MutableFieldHtml",
            "RefEncoded",
            "CapturedEncoded",
        ] {
            assert!(
                !facts(name)
                    .iter()
                    .any(|f| f.kind == OperandFactKind::EncodedHtmlOperand),
                "unsafe HTML closure: {target}/{name}"
            );
        }
        let identity = |name: &str| {
            facts(name)
                .iter()
                .find(|f| f.kind == OperandFactKind::SharedOutboundDestination)
                .map(|f| f.value.clone())
        };
        assert!(
            identity("First").is_some(),
            "missing destination identity: {target}"
        );
        assert_eq!(identity("First"), identity("Second"));
        assert_ne!(identity("First"), identity("DifferentHook"));
        assert_ne!(identity("First"), identity("DifferentRoot"));
        for name in ["RawSuffix", "ReplacedUrl"] {
            assert!(
                identity(name).is_none(),
                "unsafe destination grouping: {target}/{name}"
            );
        }
        let producer = |name: &str| {
            facts(name)
                .iter()
                .find(|f| f.kind == OperandFactKind::SharedFilesystemProducer)
                .map(|f| f.value.clone())
        };
        assert!(producer("DeleteOne").is_some());
        assert_eq!(producer("DeleteOne"), producer("DeleteTwo"));
        assert_eq!(producer("DeleteOne"), producer("DeleteInline"));
        assert_eq!(producer("DeleteOne"), producer("ReadInline"));
        assert_eq!(producer("DeleteBypass"), producer("DeleteInlineBypass"));
        assert!(producer("DeleteInlineUnknownOption").is_none());
        assert!(producer("DeleteInlineModified").is_none());
        assert_eq!(producer("DeleteOne"), producer("DeleteNamed"));
        assert_eq!(producer("DeleteBypass"), producer("DeleteNamedBypass"));
        assert_ne!(producer("DeleteOne"), producer("DeleteBypass"));
        assert_ne!(producer("DeleteOne"), producer("DeleteOther"));
        assert!(producer("DeleteReplaced").is_none());
        let native = investigation::build_review_inventory_with_semantics(
            &fixture.0,
            false,
            Some((
                &{
                    let path = fixture.0.join(format!("{target}-snapshot.json"));
                    std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
                    path
                },
                &context,
            )),
        )
        .unwrap();
        for name in ["Json", "Plain"] {
            assert!(
                plain
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(name)),
                "missing MIME baseline {name}"
            );
            assert!(
                !native
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(name)),
                "MIME review retained {name}"
            );
        }
        for name in [
            "Html",
            "Different",
            "Conditional",
            "Intervening",
            "ArgumentMutation",
        ] {
            assert!(
                native
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(name)),
                "dangerous MIME control lost {name}"
            );
        }
        for name in ["Encoded", "Child", "Fragment"] {
            assert!(
                !native
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(name)),
                "HTML proof not used in admission: {name}"
            );
        }
        for name in [
            "Raw",
            "SuppliedEncoder",
            "Replaced",
            "RawChild",
            "LaterRawChild",
            "AliasedChild",
            "Link",
            "Script",
            "RawSuffix",
            "ReplacedUrl",
        ] {
            assert!(
                native
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(name)),
                "lost unsafe case: {name}"
            );
        }
        let shared = native
            .entries
            .iter()
            .filter(|e| {
                e.value_hint
                    .as_ref()
                    .is_some_and(|h| h.reason == "shared_csharp_outbound_destination")
            })
            .collect::<Vec<_>>();
        assert_eq!(shared.len(), 1);
        let path_shared = native
            .entries
            .iter()
            .filter(|e| {
                e.value_hint
                    .as_ref()
                    .is_some_and(|h| h.reason == "shared_csharp_filesystem_producer")
            })
            .collect::<Vec<_>>();
        assert_eq!(path_shared.len(), 6);
        assert!(
            native
                .entries
                .iter()
                .find(|e| e.symbol.as_deref() == Some("Read"))
                .unwrap()
                .value_hint
                .is_none()
        );
        assert!(shared[0].value_hint.as_ref().unwrap().depends_on.is_some());
        assert_eq!(
            plain
                .scan
                .evidence
                .iter()
                .map(|e| &e.id)
                .collect::<Vec<_>>(),
            native
                .scan
                .evidence
                .iter()
                .map(|e| &e.id)
                .collect::<Vec<_>>()
        );
        assert_eq!(baseline.security_paths, native.scan.security_paths);
        let mut enriched = baseline.clone();
        csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut enriched).unwrap();
        assert_eq!(baseline.coverage, enriched.coverage);
    }
}

#[test]
#[ignore = "requires Roslyn helper and real .NET 10 refs"]
fn declared_global_imports_bind_framework_calls_and_invalidate_snapshots() {
    let fixture = Fixture::new("global-imports");
    std::fs::write(fixture.0.join("App.cs"), "class App { void Delete() { File.Delete(Path.Combine(AppContext.BaseDirectory, Guid.NewGuid().ToString())); } }").unwrap();
    std::fs::write(fixture.0.join("Helpers.cs"), "").unwrap();
    let context = fixture.context(
        "imports",
        "net10.0",
        "14.0",
        &env_path("MEHSCAN_ROSLYN_NET10_REFS"),
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let missing = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    assert!(
        !missing
            .observations
            .iter()
            .flat_map(|o| &o.facts)
            .any(|f| f.kind == OperandFactKind::FixedFilesystemPath)
    );
    let mut declared: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&context).unwrap()).unwrap();
    declared["projects"][0]["global_usings"] = json!(["System", "System.IO"]);
    std::fs::write(&context, serde_json::to_vec(&declared).unwrap()).unwrap();
    let bound = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    assert!(
        bound
            .observations
            .iter()
            .flat_map(|o| &o.facts)
            .any(|f| f.kind == OperandFactKind::FixedFilesystemPath)
    );
    let mut enriched = scan.clone();
    csharp_semantic::enrich(&fixture.0, &context, &bound, &mut enriched).unwrap();
    declared["projects"][0]["global_usings"] = json!(["System"]);
    std::fs::write(&context, serde_json::to_vec(&declared).unwrap()).unwrap();
    assert!(csharp_semantic::enrich(&fixture.0, &context, &bound, &mut enriched).is_err());
}

#[test]
#[ignore = "requires built Roslyn helper and real four-framework reference packs"]
fn source_project_references_carry_selectors_and_bind_dependency_inputs() {
    let fixture = Fixture::new("source-projects");
    std::fs::write(
        fixture.0.join("App.cs"),
        r#"
using System;
using System.IO;
class App {
    void Known(Guid id) { File.Delete(Selectors.Path("data", id)); }
    void Unknown(string root, Guid id) { File.Delete(Selectors.Path(root, id)); }
    void Property(Record record) { File.Delete(Path.Combine("data", record.Name)); }
    void UnknownProperty(Record record) { File.Delete(Path.Combine("data", record.RawName)); }
}
"#,
    )
    .unwrap();
    let helper = r#"
using System;
using System.IO;
public static class Selectors {
    public static string Path(string root, Guid id) => System.IO.Path.Combine(root, id.ToString("N"));
}
public class Record {
    public Guid Id { get; set; }
    public string Name => Id.ToString("N") + ".json";
    public string RawName { get; set; }
}
class UnrelatedGap { MissingType field; }
"#;
    std::fs::write(fixture.0.join("Helpers.cs"), helper).unwrap();
    let dormant = "class UnqueriedProject { UnknownType field; }";
    std::fs::write(fixture.0.join("Dormant.cs"), dormant).unwrap();
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    for (label, target, language, refs) in [
        ("net8", "net8.0", "12.0", "MEHSCAN_ROSLYN_NET8_REFS"),
        ("net10", "net10.0", "14.0", "MEHSCAN_ROSLYN_NET10_REFS"),
        ("net48", "net48", "7.3", "MEHSCAN_ROSLYN_NET48_REFS"),
        (
            "standard",
            "netstandard2.0",
            "7.3",
            "MEHSCAN_ROSLYN_STANDARD20_REFS",
        ),
    ] {
        let refs: Vec<_> = std::fs::read_dir(env_path(refs))
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|e| e == "dll")
                    && !p
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("System.EnterpriseServices.")
            })
            .collect();
        let context = fixture.0.join(format!("{label}.json"));
        let mut declared = json!({"projects": [
            {"id":"src/App.csproj", "target_framework":target, "language_version":language,
             "sources":["App.cs"], "references":refs, "reference_directories":[], "defines":[],
             "project_references":["src/Selectors.csproj"]},
            {"id":"src/Selectors.csproj", "target_framework":target, "language_version":language,
             "sources":["Helpers.cs"], "references":refs, "reference_directories":[], "defines":[]},
            {"id":"src/Dormant.csproj", "target_framework":target, "language_version":language,
             "sources":["Dormant.cs"], "references":refs, "reference_directories":[], "defines":[]}
        ]});
        std::fs::write(&context, serde_json::to_vec(&declared).unwrap()).unwrap();
        let snapshot = csharp_semantic::collect(
            &fixture.0,
            &context,
            &env_path("MEHSCAN_ROSLYN_BACKEND"),
            &scan,
        )
        .unwrap();
        let serialized = serde_json::to_value(&snapshot).unwrap();
        let caller = serialized["projects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "src/App.csproj")
            .unwrap();
        assert_eq!(caller["compiler_errors"], 0);
        assert_eq!(caller["incomplete_dependencies"], true);
        assert_eq!(caller["semantic_analysis"], "performed");
        let records = serialized["projects"].as_array().unwrap();
        assert_eq!(
            records
                .iter()
                .find(|p| p["id"] == "src/Selectors.csproj")
                .unwrap()["semantic_analysis"],
            "performed"
        );
        assert_eq!(
            records
                .iter()
                .find(|p| p["id"] == "src/Dormant.csproj")
                .unwrap()["semantic_analysis"],
            "not_requested"
        );
        assert!(
            serialized["sources"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["path"] == "Dormant.cs")
        );
        // Skipped project inputs remain bound, and cannot supply observations.
        std::fs::write(fixture.0.join("Dormant.cs"), "class Changed {}").unwrap();
        assert!(
            csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut scan.clone()).is_err()
        );
        std::fs::write(fixture.0.join("Dormant.cs"), dormant).unwrap();
        let mut forged = serialized.clone();
        forged["projects"][0]["semantic_analysis"] = json!("not_requested");
        let forged: csharp_semantic::Snapshot = serde_json::from_value(forged).unwrap();
        assert!(csharp_semantic::enrich(&fixture.0, &context, &forged, &mut scan.clone()).is_err());
        let mut enriched = scan.clone();
        csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut enriched).unwrap();
        assert!(
            enriched
                .evidence
                .iter()
                .filter(|e| e.enclosing_symbol.as_deref() == Some("Unknown"))
                .flat_map(|e| &e.context.operand_facts)
                .any(|f| f
                    .remaining_checks
                    .iter()
                    .any(|c| c == "partial_semantic_context"))
        );
        let path = fixture.0.join("snapshot.json");
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let inventory = investigation::build_review_inventory_with_semantics(
            &fixture.0,
            false,
            Some((&path, &context)),
        )
        .unwrap();
        for closed in ["Known", "Property"] {
            assert!(
                !inventory
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(closed)),
                "{label}: normalized selector lost through referenced source project: {closed}"
            );
        }
        for open in ["Unknown", "UnknownProperty"] {
            assert!(
                inventory
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(open)),
                "{label}: unknown source input incorrectly closed: {open}"
            );
        }
        std::fs::write(
            fixture.0.join("Helpers.cs"),
            helper.replace("id.ToString(\"N\")", "Console.ReadLine()"),
        )
        .unwrap();
        assert!(
            csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut scan.clone()).is_err()
        );
        std::fs::write(fixture.0.join("Helpers.cs"), helper).unwrap();
        declared["projects"][0]["project_references"] = json!([]);
        std::fs::write(&context, serde_json::to_vec(&declared).unwrap()).unwrap();
        let unlinked = csharp_semantic::collect(
            &fixture.0,
            &context,
            &env_path("MEHSCAN_ROSLYN_BACKEND"),
            &scan,
        )
        .unwrap();
        assert!(
            !unlinked
                .observations
                .iter()
                .flat_map(|o| &o.facts)
                .any(|f| f.kind == OperandFactKind::FixedFilesystemPath)
        );
        declared["projects"][0]["project_references"] = json!(["missing-context"]);
        std::fs::write(&context, serde_json::to_vec(&declared).unwrap()).unwrap();
        assert!(
            csharp_semantic::collect(
                &fixture.0,
                &context,
                &env_path("MEHSCAN_ROSLYN_BACKEND"),
                &scan
            )
            .is_err()
        );
        declared["projects"][0]["project_references"] = json!(["src/Selectors.csproj"]);
        declared["projects"][1]["assembly_name"] =
            json!(refs[0].file_stem().unwrap().to_string_lossy());
        std::fs::write(&context, serde_json::to_vec(&declared).unwrap()).unwrap();
        let collision = csharp_semantic::collect(
            &fixture.0,
            &context,
            &env_path("MEHSCAN_ROSLYN_BACKEND"),
            &scan,
        )
        .unwrap();
        assert!(
            !collision
                .observations
                .iter()
                .flat_map(|o| &o.facts)
                .any(|f| f.kind == OperandFactKind::FixedFilesystemPath)
        );
        declared["projects"][1]
            .as_object_mut()
            .unwrap()
            .remove("assembly_name");
        declared["projects"][2]["project_references"] = json!(["src/Dormant.csproj"]);
        std::fs::write(&context, serde_json::to_vec(&declared).unwrap()).unwrap();
        assert!(
            csharp_semantic::collect(
                &fixture.0,
                &context,
                &env_path("MEHSCAN_ROSLYN_BACKEND"),
                &scan
            )
            .is_err()
        );
        declared["projects"][2]["project_references"] = json!([]);
        declared["projects"][1]["project_references"] = json!(["src/App.csproj"]);
        std::fs::write(&context, serde_json::to_vec(&declared).unwrap()).unwrap();
        assert!(
            csharp_semantic::collect(
                &fixture.0,
                &context,
                &env_path("MEHSCAN_ROSLYN_BACKEND"),
                &scan
            )
            .is_err()
        );
    }
}

#[test]
#[ignore = "requires built Roslyn helper and real four-framework reference packs"]
fn filesystem_proofs_are_complete_and_unknown_paths_stay_reviewable() {
    let fixture = Fixture::new("filesystem");
    for file in ["App.cs", "Helpers.cs"] {
        std::fs::write(fixture.0.join(file), "").unwrap();
    }
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/roslyn-filesystem/Paths.cs"),
        fixture.0.join("App.cs"),
    )
    .unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/roslyn-filesystem/Selectors.cs"),
        fixture.0.join("Helpers.cs"),
    )
    .unwrap();
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let plain = investigation::build_review_inventory(&fixture.0, false).unwrap();
    for (label, target, language, refs) in [
        ("net8", "net8.0", "12.0", "MEHSCAN_ROSLYN_NET8_REFS"),
        ("net10", "net10.0", "14.0", "MEHSCAN_ROSLYN_NET10_REFS"),
        ("net48", "net48", "7.3", "MEHSCAN_ROSLYN_NET48_REFS"),
        (
            "standard",
            "netstandard2.0",
            "7.3",
            "MEHSCAN_ROSLYN_STANDARD20_REFS",
        ),
    ] {
        let context = fixture.context(label, target, language, &env_path(refs));
        if target == "net48" {
            // The reference pack also contains two native COM helper DLLs.
            // Supply managed references explicitly rather than declaring them as assemblies.
            let references = std::fs::read_dir(env_path(refs))
                .unwrap()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|e| e == "dll")
                        && !p
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with("System.EnterpriseServices.")
                })
                .collect::<Vec<_>>();
            let mut declared: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&context).unwrap()).unwrap();
            declared["projects"][0]["reference_directories"] = json!([]);
            declared["projects"][0]["references"] = json!(references);
            std::fs::write(&context, serde_json::to_vec(&declared).unwrap()).unwrap();
        }
        let snapshot = csharp_semantic::collect(
            &fixture.0,
            &context,
            &env_path("MEHSCAN_ROSLYN_BACKEND"),
            &scan,
        )
        .unwrap();
        assert!(
            snapshot.diagnostics.is_empty(),
            "{label}: {:?}",
            snapshot.diagnostics
        );
        let mut enriched = scan.clone();
        csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut enriched).unwrap();
        assert_eq!(scan.security_paths, enriched.security_paths);
        for (old, new) in scan.evidence.iter().zip(&enriched.evidence) {
            assert_eq!(old.id, new.id);
            assert_eq!(old.captures, new.captures);
        }
        let fact = |method: &str, kind: OperandFactKind| {
            enriched
                .evidence
                .iter()
                .filter(|e| {
                    e.enclosing_symbol.as_deref() == Some(method)
                        && e.capability == Capability::FilesystemWrite
                })
                .any(|e| e.context.operand_facts.iter().any(|f| f.kind == kind))
        };
        for method in [
            "FixedReset",
            "FixedAlias",
            "FixedCombine",
            "FixedNumber",
            "FixedBoolean",
            "GuidParameter",
            "GuidFormat",
            "GuidProvider",
            "GuidSuffix",
            "UnknownNumber",
            "ParsedNumber",
            "IntegralFormat",
            "IntegralInvariant",
            "IntegralStandardFormat",
            "DecimalValue",
            "FloatingValue",
            "DateBackupSuffix",
            "DateDefault",
            "DateStandard",
            "DateOffset",
            "Duration",
            "NullableDate",
            "NullableNumber",
            "NumericCustom",
            "CultureDate",
            "BoxedConversion",
            "NumericConcat",
            "DateConcat",
            "GuidConcat",
            "Character",
            "HelperGuid",
            "HelperDate",
            "HelperRootGuid",
            "PropertyGuid",
            "PropertyDate",
            "PropertyInitialized",
            "BooleanValue",
            "ConvertedNumber",
            "EnumValue",
            "DateFilename",
            "InterpolatedId",
            "InterpolatedNumber",
            "RuntimeRoot",
            "DomainRoot",
            "WorkingRoot",
            "FolderRoot",
            "ParentOfKnownPath",
            "FixedArrayCombine",
            "EnumeratedFiles",
            "FirstFile",
            "KnownFileInfo",
            "ReadonlyPath",
            "ClosedBranches",
            "TempFinally",
        ] {
            assert!(
                fact(method, OperandFactKind::FixedFilesystemPath),
                "{label}: {method}"
            );
        }
        for method in [
            "TempGuid",
            "TempRandom",
            "TempAlias",
            "TempFile",
            "TempReads",
            "TempResetInTry",
            "TempCapturedRead",
            "TempExecutable",
            "TempSuffixReset",
            "PrivateTempDelete",
        ] {
            assert!(
                fact(method, OperandFactKind::TemporaryFilesystemPath),
                "{label}: {method}"
            );
        }
        for method in [
            "ConditionalReset",
            "Accumulation",
            "UnknownRoot",
            "UnknownManifest",
            "FormatInput",
            "RefReplacement",
            "HelperUnknownRoot",
            "HelperUnknownString",
            "HelperReplacedString",
            "HelperRecursive",
            "PropertyUnknown",
            "PropertyVirtual",
            "PropertyReplaced",
            "DateUnknownRoot",
            "DateUnknownFormat",
            "Capture",
            "TryReplacement",
            "Conversion",
            "PrivateUnknownDelete",
            "MutatingConstructorDelete",
            "PublicOwnerDelete",
            "PartialReadonlyDelete",
            "GuidUnknownRoot",
            "GuidUnknownFilename",
            "GuidLookalike",
            "TempConditionalInTry",
            "UnknownInterpolation",
            "UnknownNumericFormat",
            "UnknownNumericProvider",
            "ParentOfUnknownPath",
            "EnumeratedUnknownRoot",
            "MutatedFiles",
            "EscapedFiles",
            "OverwrittenReadonly",
            "ReplacedReadonly",
            "MixedBranches",
            "LoopReplacement",
        ] {
            assert!(
                !fact(method, OperandFactKind::FixedFilesystemPath),
                "{label}: {method}"
            );
            assert!(
                !fact(method, OperandFactKind::TemporaryFilesystemPath),
                "{label}: {method}"
            );
        }
        let path = fixture.0.join(format!("{label}-snapshot.json"));
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let inventory = investigation::build_review_inventory_with_semantics(
            &fixture.0,
            false,
            Some((&path, &context)),
        )
        .unwrap();
        assert!(inventory.entries.len() < plain.entries.len());
        assert!(
            inventory
                .admission_audit
                .closed_operands
                .iter()
                .any(|closed| closed
                    .operand_fact
                    .as_ref()
                    .is_some_and(|fact| fact.kind == OperandFactKind::FixedFilesystemPath))
        );
        assert!(
            !inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some("FixedReset"))
        );
        for method in [
            "GuidParameter",
            "GuidFormat",
            "GuidProvider",
            "GuidSuffix",
            "UnknownNumber",
            "ParsedNumber",
            "IntegralFormat",
            "IntegralInvariant",
            "IntegralStandardFormat",
            "DecimalValue",
            "FloatingValue",
            "DateBackupSuffix",
            "DateDefault",
            "DateStandard",
            "DateOffset",
            "Duration",
            "NullableDate",
            "NullableNumber",
            "NumericCustom",
            "CultureDate",
            "BoxedConversion",
            "NumericConcat",
            "DateConcat",
            "GuidConcat",
            "Character",
            "HelperGuid",
            "HelperDate",
            "HelperRootGuid",
            "PropertyGuid",
            "PropertyDate",
            "PropertyInitialized",
            "BooleanValue",
            "ConvertedNumber",
            "EnumValue",
            "DateFilename",
            "InterpolatedId",
            "InterpolatedNumber",
            "RuntimeRoot",
            "DomainRoot",
            "WorkingRoot",
            "FolderRoot",
            "ParentOfKnownPath",
            "FixedArrayCombine",
            "EnumeratedFiles",
            "FirstFile",
            "KnownFileInfo",
            "ReadonlyPath",
            "ClosedBranches",
        ] {
            assert!(
                !inventory
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(method)),
                "{label}: leftover {method}"
            );
        }
        for method in [
            "TempGuid",
            "TempRandom",
            "TempAlias",
            "TempFile",
            "TempReads",
            "TempResetInTry",
            "TempCapturedRead",
            "TempExecutable",
            "TempFinally",
            "TempSuffixReset",
        ] {
            assert!(
                !inventory
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(method)),
                "{label}: {method}"
            );
            assert!(
                inventory
                    .admission_audit
                    .closed_operands
                    .iter()
                    .any(|closed| closed
                        .operand_fact
                        .as_ref()
                        .is_some_and(|fact| fact.kind == OperandFactKind::TemporaryFilesystemPath))
            );
        }
        for method in [
            "ConditionalReset",
            "Accumulation",
            "UnknownRoot",
            "UnknownManifest",
            "FormatInput",
            "RefReplacement",
            "HelperUnknownRoot",
            "HelperUnknownString",
            "HelperReplacedString",
            "HelperRecursive",
            "PropertyUnknown",
            "PropertyVirtual",
            "PropertyReplaced",
            "DateUnknownRoot",
            "DateUnknownFormat",
            "Capture",
            "TryReplacement",
            "Conversion",
            "GuidUnknownRoot",
            "GuidUnknownFilename",
            "GuidLookalike",
            "UnknownInterpolation",
            "UnknownNumericFormat",
            "UnknownNumericProvider",
            "ParentOfUnknownPath",
            "EnumeratedUnknownRoot",
            "MutatedFiles",
            "EscapedFiles",
            "OverwrittenReadonly",
            "ReplacedReadonly",
            "MixedBranches",
            "LoopReplacement",
        ] {
            assert!(
                inventory
                    .entries
                    .iter()
                    .any(|e| e.symbol.as_deref() == Some(method)
                        && (e.value_hint.is_none()
                            || e.value_hint.as_ref().is_some_and(
                                |h| h.reason == "ordinary_directory_creation_inventory"
                            ))),
                "{label}: {method}"
            );
        }
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some("TempConditionalInTry")
                    && e.value_hint
                        .as_ref()
                        .is_some_and(|h| h.reason == "ordinary_directory_creation_inventory")),
            "{label}: unknown directory creation stays in Comprehensive, not safely suppressed"
        );
        if label == "net10" {
            let mut malformed = serde_json::to_value(&snapshot).unwrap();
            let fact = malformed["observations"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .flat_map(|o| o["facts"].as_array_mut().unwrap())
                .find(|f| f["kind"] == "temporary_filesystem_path")
                .unwrap();
            fact["value"] = json!("invented safe path");
            let malformed = serde_json::from_value(malformed).unwrap();
            assert!(
                csharp_semantic::enrich(&fixture.0, &context, &malformed, &mut scan.clone())
                    .is_err()
            );
            std::fs::write(
                fixture.0.join("Helpers.cs"),
                format!(
                    "{}\nclass Broken {{ MissingType field; }}",
                    std::fs::read_to_string(fixture.0.join("Helpers.cs")).unwrap()
                ),
            )
            .unwrap();
            let partial_scan = mehscan_engine::scan_path(&fixture.0).unwrap();
            let partial = csharp_semantic::collect(
                &fixture.0,
                &context,
                &env_path("MEHSCAN_ROSLYN_BACKEND"),
                &partial_scan,
            )
            .unwrap();
            std::fs::write(&path, serde_json::to_vec(&partial).unwrap()).unwrap();
            let partial_inventory = investigation::build_review_inventory_with_semantics(
                &fixture.0,
                false,
                Some((&path, &context)),
            )
            .unwrap();
            assert_eq!(
                inventory
                    .entries
                    .iter()
                    .map(|e| &e.review_id)
                    .collect::<Vec<_>>(),
                partial_inventory
                    .entries
                    .iter()
                    .map(|e| &e.review_id)
                    .collect::<Vec<_>>()
            );
            // Missing dependencies on an unrelated declaration do not turn
            // bounded, uniquely resolved framework producers back into reviews.
            assert!(partial_inventory.entries.iter().all(|e| {
                e.value_hint.is_none()
                    || e.value_hint
                        .as_ref()
                        .is_some_and(|h| h.reason == "ordinary_directory_creation_inventory")
            }));
            std::fs::write(fixture.0.join("Helpers.cs"), "class Broken { void Unbound(string path) { Missing.Delete(path); } void BadLocal() { var path = \"known\"; Missing.Replace(ref path); System.IO.File.Delete(path); } }").unwrap();
            let broken_scan = mehscan_engine::scan_path(&fixture.0).unwrap();
            let broken = csharp_semantic::collect(
                &fixture.0,
                &context,
                &env_path("MEHSCAN_ROSLYN_BACKEND"),
                &broken_scan,
            )
            .unwrap();
            assert!(
                !broken
                    .observations
                    .iter()
                    .flat_map(|o| &o.facts)
                    .any(|f| f.location.path == "Helpers.cs"
                        && matches!(
                            f.kind,
                            OperandFactKind::FixedFilesystemPath
                                | OperandFactKind::TemporaryFilesystemPath
                        ))
            );
            std::fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/roslyn-filesystem/Selectors.cs"),
                fixture.0.join("Helpers.cs"),
            )
            .unwrap();
        }
    }
}

#[test]
#[ignore = "requires built Roslyn helper and real .NET 8 / 10, Standard 2.0 and Framework 4.8 packs"]
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
        (
            "current",
            "net10.0",
            "14.0",
            "MEHSCAN_ROSLYN_NET10_REFS",
            "System.Data.Common, Version=10.0.0.0",
        ),
        (
            "standard",
            "netstandard2.0",
            "7.3",
            "MEHSCAN_ROSLYN_STANDARD20_REFS",
            "netstandard, Version=2.0.0.0",
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
        assert!(raw.context.operand_facts.iter().any(|f| {
            f.role == "sink"
                && f.kind == OperandFactKind::SemanticIdentity
                && f.remaining_checks
                    .iter()
                    .any(|c| c == "caller_or_entrypoint_reachability")
        }));
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
                    && f.value.contains("CFG possible local producer set"))
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
                .any(|f| f.role == "query" && f.kind == OperandFactKind::SemanticDefinition)
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
        let original = std::fs::read(&context).unwrap();
        let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
        changed["projects"][0]["defines"] = json!(["ALTERED_AFTER_INVENTORY"]);
        std::fs::write(&context, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            investigation::build_selected_review_jobs(&fixture.0, &inventory, &selected, Some(4))
                .unwrap_err()
                .0
                .contains("context is stale")
        );
        std::fs::write(&context, original).unwrap();
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
    assert!(with_reference.observations.is_empty());
    assert!(
        with_reference
            .diagnostics
            .iter()
            .any(|d| d["code"] == "MEHSCAN_REFERENCE_CONFLICT")
    );
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
    assert!(!facts.iter().any(|f| f.role == "receiver"));
    assert!(facts.iter().any(|f| f.role == "query"
        && f.kind == OperandFactKind::SemanticDefinition
        && f.location.path == "nested/Helpers.cs"));
}

#[test]
#[ignore = "requires built Roslyn helper and real .NET 8 reference pack"]
fn local_write_navigation_distinguishes_resets_branches_and_same_spelling_locals() {
    let fixture = Fixture::new("local-writes");
    // The source-defined Query supplies a compiler-bound call shape only;
    // this control makes no claim about Dapper behavior or SQL safety.
    let source = r#"using System.Data.Common;
using Dapper;
namespace Dapper {
    static class QueryApi { public static string Query(this DbConnection db, string sql) => sql; }
}
class Writes {
    static void Read(string value) { }
    static void Mutate(ref string value) { }
    void Reset(DbConnection db, string input) {
        var query = input;
        query += " first";
        Read(query);
        query = "SELECT 1";
        query += " old";
        query = "SELECT 2";
        query += " final";
        using DbCommand command = db.CreateCommand();
        command.CommandText = query;
    }
    void Append(DbCommand command, string input) {
        var query = input;
        query += " first";
        query += " final";
        command.CommandText = query;
    }
    void Conditional(DbCommand command, string input, bool flag) {
        var query = input;
        if (flag) query = "SELECT 3";
        command.CommandText = query;
    }
    void Shadow(DbCommand command, string input) {
        { var query = "SELECT 4";
          query = input;
          command.CommandText = query; }
        { var query = "SELECT 5";
          command.CommandText = query; }
    }
    void ReadOnly(DbCommand command, string input) {
        var query = input;
        Read(query);
        command.CommandText = query;
    }
    void Handoff(DbCommand command, string input) {
        var query = input;
        Mutate(ref query);
        command.CommandText = query;
    }
    void Captured(DbCommand command, string input) {
        var query = input;
        System.Action change = () => { query = "SELECT 6"; };
        command.CommandText = query;
    }
    void Overlapping(DbConnection db, string input) {
        var query = input;
        query = db.Query(query);
    }
}
"#;
    std::fs::write(fixture.0.join("App.cs"), source).unwrap();
    let context = fixture.context(
        "writes",
        "net8.0",
        "12.0",
        &env_path("MEHSCAN_ROSLYN_NET8_REFS"),
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let snapshot = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    assert_eq!(snapshot.observations.len(), 9);
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["projects"][0]["compiler_errors"],
        0
    );
    let native_query = |method: &str| {
        scan.evidence
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some(method))
            .flat_map(|e| {
                snapshot
                    .observations
                    .iter()
                    .filter(move |o| o.evidence_id == e.id)
            })
            .flat_map(|o| &o.facts)
            .filter(|f| f.role == "query")
            .collect::<Vec<_>>()
    };
    for (method, expected) in [
        ("Reset", vec!["\"SELECT 2\"", "\" final\""]),
        ("Append", vec!["input", "\" first\"", "\" final\""]),
        ("Conditional", vec!["input", "\"SELECT 3\""]),
        ("ReadOnly", vec!["input"]),
        ("Overlapping", vec!["input"]),
    ] {
        let facts = native_query(method);
        let boundary = facts
            .iter()
            .find(|f| f.kind == OperandFactKind::OperandBoundary)
            .unwrap();
        assert!(
            boundary.value.contains("CFG possible local producer set"),
            "{method}"
        );
        assert!(
            boundary
                .remaining_checks
                .iter()
                .any(|c| c == "branch_feasibility_and_accumulation")
        );
        let actual: Vec<_> = facts
            .iter()
            .filter(|f| f.kind == OperandFactKind::LocalOperandOrigin)
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(actual, expected, "{method}");
    }
    for method in ["Handoff", "Captured"] {
        let facts = native_query(method);
        assert!(
            facts
                .iter()
                .any(|f| f.kind == OperandFactKind::OperandBoundary
                    && (f.value.contains("Intervening reference") || f.value.contains("captured"))),
            "{method}"
        );
        assert!(
            !facts
                .iter()
                .any(|f| f.kind == OperandFactKind::LocalOperandOrigin),
            "{method}"
        );
    }
    let shadow = native_query("Shadow");
    assert_eq!(
        shadow
            .iter()
            .filter(|f| f.kind == OperandFactKind::OperandBoundary)
            .count(),
        1
    );
    assert!(
        shadow
            .iter()
            .any(|f| f.kind == OperandFactKind::LocalOperandOrigin && f.value == "\"SELECT 5\"")
    );
    let mut enriched = scan.clone();
    csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut enriched).unwrap();
    assert_eq!(
        scan.evidence.iter().map(|e| &e.id).collect::<Vec<_>>(),
        enriched.evidence.iter().map(|e| &e.id).collect::<Vec<_>>()
    );
    assert_eq!(scan.security_paths, enriched.security_paths);
}

#[test]
#[ignore = "requires Roslyn helper, .NET 8 refs and Microsoft.Data.SqlClient 5.2.1 ref assembly"]
fn receiver_navigation_tracks_exact_locals_and_stops_without_state_verdicts() {
    let fixture = Fixture::new("receivers");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/roslyn-receiver/App.cs"),
        fixture.0.join("App.cs"),
    )
    .unwrap();
    let mut source = std::fs::read_to_string(fixture.0.join("App.cs")).unwrap();
    source.push_str("\npublic class Aliases\n{\n    public void FromOther(SqlCommand other, string input)\n    {\n        SqlCommand command = other;\n        command.CommandText = \"SELECT * FROM Items WHERE Name='\" + input + \"'\";\n        command.ExecuteReader();\n    }\n}\n");
    std::fs::write(fixture.0.join("App.cs"), source).unwrap();
    let context = fixture.context(
        "receivers",
        "net8.0",
        "12.0",
        &env_path("MEHSCAN_ROSLYN_NET8_REFS"),
    );
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&context).unwrap()).unwrap();
    document["projects"][0]["sources"] = json!(["App.cs"]);
    document["projects"][0]["references"] = json!([env_path("MEHSCAN_ROSLYN_SQLCLIENT_REF")]);
    std::fs::write(&context, serde_json::to_vec(&document).unwrap()).unwrap();
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let snapshot = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["projects"][0]["compiler_errors"],
        0
    );
    let mut enriched = scan.clone();
    csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut enriched).unwrap();
    let facts = |name: &str| {
        enriched
            .evidence
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some(name))
            .flat_map(|e| e.context.operand_facts.iter())
            .filter(|f| f.role == "receiver")
            .collect::<Vec<_>>()
    };
    for method in [
        "Constructed",
        "Assigned",
        "Empty",
        "Passed",
        "Replaced",
        "Captured",
        "Conditional",
        "Many",
        "Shadow",
    ] {
        assert!(
            facts(method)
                .iter()
                .any(|f| f.kind == OperandFactKind::LocalOperandOrigin),
            "{method}"
        );
        assert!(
            facts(method)
                .iter()
                .any(|f| f.kind == OperandFactKind::SemanticIdentity
                    && f.value
                        .contains("Microsoft.Data.SqlClient, Version=5.0.0.0")),
            "{method}"
        );
    }
    for method in ["Constructed", "Assigned", "Empty", "Conditional", "Shadow"] {
        assert!(
            facts(method)
                .iter()
                .any(|f| f.kind == OperandFactKind::ReceiverReference
                    && f.value == "command.ExecuteReader()"),
            "{method}"
        );
        assert!(
            facts(method)
                .iter()
                .any(|f| f.value.contains("no runtime state inferred")),
            "{method}"
        );
    }
    assert!(
        facts("Assigned")
            .iter()
            .any(|f| f.value == "command.Connection = connection")
    );
    assert!(
        facts("Conditional")
            .iter()
            .any(|f| f.value == "command.Connection = connection")
    );
    for method in ["Passed", "Replaced", "Captured"] {
        assert!(
            facts(method).iter().any(|f| f
                .remaining_checks
                .iter()
                .any(|c| c == "receiver_replacement_alias_capture_or_handoff")),
            "{method}"
        );
        assert!(
            !facts(method)
                .iter()
                .any(|f| f.value.contains("no runtime state inferred")),
            "{method}"
        );
    }
    assert!(
        !facts("Passed")
            .iter()
            .any(|f| f.value == "command.ExecuteReader()")
    );
    assert!(facts("Many").iter().any(|f| {
        f.remaining_checks
            .iter()
            .any(|c| c == "remaining_receiver_references")
    }));
    assert!(!facts("Shadow").iter().any(|f| f.value.contains("42")));
    assert!(
        facts("FromOther").iter().any(|f| {
            f.remaining_checks
                .iter()
                .any(|c| c == "receiver_origin_alias_or_factory")
        }),
        "FromOther receiver facts: {:?}",
        facts("FromOther")
    );
    assert!(
        !facts("FromOther")
            .iter()
            .any(|f| f.kind == OperandFactKind::ReceiverReference)
    );
    // Source facts are validated before any scan mutation, not trusted strings.
    let mut forged: csharp_semantic::Snapshot =
        serde_json::from_value(serde_json::to_value(&snapshot).unwrap()).unwrap();
    forged
        .observations
        .iter_mut()
        .flat_map(|o| &mut o.facts)
        .find(|f| f.kind == OperandFactKind::ReceiverReference)
        .unwrap()
        .value
        .push_str(" altered");
    let mut unchanged = scan.clone();
    assert!(
        csharp_semantic::enrich(&fixture.0, &context, &forged, &mut unchanged)
            .unwrap_err()
            .0
            .contains("does not match source")
    );
    assert_eq!(unchanged, scan);
}

#[test]
#[ignore = "requires Roslyn helper, .NET 8 and SqlClient metadata"]
fn cfg_producers_cover_mixed_parts_joins_loops_and_unsupported_shapes() {
    let fixture = Fixture::new("cfg-controls");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/roslyn-flow/App.cs"),
        fixture.0.join("App.cs"),
    )
    .unwrap();
    let context = fixture.context(
        "flow",
        "net8.0",
        "12.0",
        &env_path("MEHSCAN_ROSLYN_NET8_REFS"),
    );
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&context).unwrap()).unwrap();
    document["projects"][0]["sources"] = json!(["App.cs"]);
    document["projects"][0]["references"] = json!([env_path("MEHSCAN_ROSLYN_SQLCLIENT_REF")]);
    std::fs::write(&context, serde_json::to_vec(&document).unwrap()).unwrap();
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let snapshot = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["projects"][0]["compiler_errors"],
        0
    );
    let facts = |method: &str| {
        scan.evidence
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some(method))
            .flat_map(|e| {
                snapshot
                    .observations
                    .iter()
                    .filter(move |o| o.evidence_id == e.id)
            })
            .flat_map(|o| &o.facts)
            .filter(|f| f.role == "query")
            .collect::<Vec<_>>()
    };
    for (method, required, forbidden) in [
        ("Reset", vec!["\"SELECT 1\""], Some("input")),
        ("Conditional", vec!["\"SELECT 1\"", "input"], None),
        ("Append", vec!["input", "\"'\""], None),
        (
            "BothBranches",
            vec!["\"SELECT 1\"", "\"SELECT 2\""],
            Some("input"),
        ),
        ("Loop", vec!["\"SELECT 1\"", "input"], None),
    ] {
        let native = facts(method);
        assert!(
            native
                .iter()
                .any(|f| f.value.contains("CFG possible local producer set")),
            "{method}"
        );
        let producers: Vec<_> = native
            .iter()
            .filter(|f| f.kind == OperandFactKind::LocalOperandOrigin)
            .map(|f| f.value.as_str())
            .collect();
        for value in required {
            assert!(
                producers.iter().any(|p| p.contains(value)),
                "{method}: missing {value}: {producers:?}"
            );
        }
        if let Some(value) = forbidden {
            assert!(
                !producers.iter().any(|p| p.contains(value)),
                "{method}: stale {value}"
            );
        }
    }
    for method in ["Tuple", "LateCapture"] {
        let native = facts(method);
        assert!(
            native
                .iter()
                .any(|f| f.kind == OperandFactKind::OperandBoundary),
            "{method}"
        );
        assert!(
            !native
                .iter()
                .any(|f| f.kind == OperandFactKind::LocalOperandOrigin),
            "{method}"
        );
    }
    assert!(
        facts("Mixed")
            .iter()
            .any(|f| f.kind == OperandFactKind::LocalOperandOrigin
                && f.value.contains("{id}")
                && f.value.contains("{input}"))
    );
    assert!(facts("Helper").iter().any(|f| {
        f.kind == OperandFactKind::LocalOperandOrigin
            && f.value.contains("value")
            && f.remaining_checks
                .iter()
                .any(|c| c == "helper_argument_mapping")
    }));
    let mixed = scan
        .evidence
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("Mixed"))
        .unwrap();
    let type_facts: Vec<_> = snapshot
        .observations
        .iter()
        .find(|o| o.evidence_id == mixed.id)
        .unwrap()
        .facts
        .iter()
        .filter(|f| f.role == "query_value")
        .collect();
    assert!(
        type_facts
            .iter()
            .any(|f| f.value.contains("compiler type int"))
    );
    assert!(
        type_facts
            .iter()
            .any(|f| f.value.contains("compiler type string"))
    );
    assert!(type_facts.iter().all(|f| {
        f.remaining_checks
            .iter()
            .any(|c| c == "reaching_query_and_remaining_terms")
    }));
    let mut enriched = scan.clone();
    csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut enriched).unwrap();
    assert_eq!(scan.security_paths, enriched.security_paths);
    assert_eq!(
        scan.evidence.iter().map(|e| &e.id).collect::<Vec<_>>(),
        enriched.evidence.iter().map(|e| &e.id).collect::<Vec<_>>()
    );
}

#[test]
#[ignore = "requires Roslyn helper and real .NET 8 refs"]
fn receiver_declarations_identify_fields_and_interface_parameters_without_lifecycle_claims() {
    let fixture = Fixture::new("receiver-declarations");
    let source = "using System.Data; using System.Data.Common; class Fields { DbCommand stored; void Field(string input) { stored.CommandText = input; } void Parameter(IDbCommand command, string input) { command.CommandText = input; } }";
    std::fs::write(fixture.0.join("App.cs"), source).unwrap();
    let context = fixture.context(
        "fields",
        "net8.0",
        "12.0",
        &env_path("MEHSCAN_ROSLYN_NET8_REFS"),
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let snapshot = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    assert_eq!(snapshot.observations.len(), 2);
    for observation in &snapshot.observations {
        let declaration = observation
            .facts
            .iter()
            .find(|f| f.role == "receiver" && f.kind == OperandFactKind::SemanticDefinition)
            .unwrap();
        let text =
            &source[declaration.location.start.byte_offset..declaration.location.end.byte_offset];
        assert!(matches!(text, "stored" | "command"));
        assert!(
            declaration
                .remaining_checks
                .iter()
                .any(|c| c == "receiver_origin_and_lifecycle")
        );
        assert!(
            observation
                .facts
                .iter()
                .any(|f| f.role == "receiver" && f.kind == OperandFactKind::OperandBoundary)
        );
        assert!(
            !observation
                .facts
                .iter()
                .any(|f| f.role == "receiver" && f.kind == OperandFactKind::LocalOperandOrigin)
        );
    }
    let mut enriched = scan.clone();
    csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut enriched).unwrap();
    assert_eq!(scan.security_paths, enriched.security_paths);
}

#[test]
#[ignore = "requires Roslyn helper and real .NET 8 refs"]
fn construction_type_navigation_keeps_exact_write_values_and_an_explicit_limit() {
    let fixture = Fixture::new("construction-types");
    let many = (0..18)
        .map(|i| format!("{{ids[{i}]}}"))
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        r#"
using System.Data.Common;
static class TypedWrites {{
    public static void Reset(DbCommand command, string oldInput, int id, string currentInput) {{
        var sql = "SELECT '" + oldInput + "'";
        command.CommandText = sql;
        sql = "SELECT 1";
        sql += $" WHERE Id={{id}} AND Name='{{currentInput}}'";
        command.CommandText = sql;
    }}
    public static void Conditional(DbCommand command, string input, bool reset, int id) {{
        var sql = "SELECT '" + input + "'";
        if (reset) sql = $"SELECT {{id}}";
        command.CommandText = sql;
    }}
    public static void Many(DbCommand command, int[] ids) {{
        command.CommandText = $"SELECT {many}";
    }}
    public static void ManyBranches(DbCommand command, string input, int which) {{
        var query = input;
        switch (which) {{
            case 0: query = "SELECT 0"; break;
            case 1: query = "SELECT 1"; break;
            case 2: query = "SELECT 2"; break;
            case 3: query = "SELECT 3"; break;
            case 4: query = "SELECT 4"; break;
            case 5: query = "SELECT 5"; break;
            case 6: query = "SELECT 6"; break;
            case 7: query = "SELECT 7"; break;
            default: query = "SELECT 8"; break;
        }}
        command.CommandText = query;
    }}
}}
"#
    );
    std::fs::write(fixture.0.join("App.cs"), &source).unwrap();
    std::fs::write(fixture.0.join("Helpers.cs"), "").unwrap();
    let context = fixture.context(
        "types",
        "net8.0",
        "12.0",
        &env_path("MEHSCAN_ROSLYN_NET8_REFS"),
    );
    let mut scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    // Exercise the actual fallback capture: the query local at the sink,
    // not a preselected interpolation. This occurs in accumulated app queries.
    for evidence in &mut scan.evidence {
        if matches!(
            evidence.enclosing_symbol.as_deref(),
            Some("Reset" | "Conditional")
        ) {
            let operand = evidence.captures.get("query").unwrap().clone();
            evidence
                .captures
                .insert("query_composition".into(), operand);
        }
    }
    let snapshot = csharp_semantic::collect(
        &fixture.0,
        &context,
        &env_path("MEHSCAN_ROSLYN_BACKEND"),
        &scan,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["projects"][0]["compiler_errors"],
        0
    );
    let values = |method: &str, last: bool| {
        let matching = scan
            .evidence
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some(method))
            .collect::<Vec<_>>();
        let evidence = if last {
            matching.last().unwrap()
        } else {
            matching.first().unwrap()
        };
        snapshot
            .observations
            .iter()
            .find(|o| o.evidence_id == evidence.id)
            .unwrap()
            .facts
            .iter()
            .filter(|f| f.role == "query_value")
            .collect::<Vec<_>>()
    };
    let reset = values("Reset", true);
    let source_value = |fact: &mehscan_core::OperandFact| {
        &source[fact.location.start.byte_offset..fact.location.end.byte_offset]
    };
    assert!(
        reset
            .iter()
            .any(|f| source_value(f) == "id" && f.value.contains("compiler type int"))
    );
    assert!(
        reset
            .iter()
            .any(|f| source_value(f) == "currentInput" && f.value.contains("compiler type string"))
    );
    assert!(
        !reset
            .iter()
            .any(|f| matches!(source_value(f), "oldInput" | "sql"))
    );
    let conditional = values("Conditional", true);
    assert!(conditional.iter().any(|f| source_value(f) == "input"));
    assert!(conditional.iter().any(|f| source_value(f) == "id"));
    assert!(conditional.iter().all(|f| {
        f.remaining_checks
            .iter()
            .any(|c| c == "reaching_query_and_remaining_terms")
    }));
    let capped = values("Many", true);
    assert_eq!(
        capped
            .iter()
            .filter(|f| f.kind == OperandFactKind::SemanticIdentity)
            .count(),
        16
    );
    assert!(
        capped
            .iter()
            .any(|f| f.kind == OperandFactKind::OperandBoundary && f.value.contains("sixteen"))
    );
    let joined = scan
        .evidence
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("ManyBranches"))
        .unwrap();
    let joined_facts = &snapshot
        .observations
        .iter()
        .find(|o| o.evidence_id == joined.id)
        .unwrap()
        .facts;
    assert!(
        joined_facts
            .iter()
            .any(|f| f.role == "query" && f.kind == OperandFactKind::OperandBoundary)
    );
    assert!(
        !joined_facts
            .iter()
            .any(|f| f.role == "query" && f.value.contains("CFG possible local producer set"))
    );
    csharp_semantic::enrich(&fixture.0, &context, &snapshot, &mut scan).unwrap();
}
