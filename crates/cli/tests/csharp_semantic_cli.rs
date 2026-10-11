use serde_json::{Value, json};
use std::{fs, path::PathBuf, process::Command};

#[test]
#[ignore = "requires MEHSCAN_ROSLYN_BACKEND, MEHSCAN_ROSLYN_NET8_REFS and .NET 10 runtime"]
fn semantic_collection_import_and_saved_cards_use_real_cli() {
    let root = std::env::temp_dir().join(format!("mehscan-roslyn-cli-{}", std::process::id()));
    let artifacts = root.with_extension("run");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&artifacts).unwrap();
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/roslyn-semantic");
    for file in ["App.cs", "Helpers.cs"] {
        fs::copy(fixtures.join(file), root.join(file)).unwrap();
    }
    let context = artifacts.join("context.json");
    let seed = artifacts.join("seed.json");
    let assets = artifacts.join("project.assets.json");
    let snapshot = artifacts.join("semantic.json");
    let inventory = artifacts.join("inventory");
    let bundles = artifacts.join("bundles");
    let backend = std::env::var("MEHSCAN_ROSLYN_BACKEND").unwrap();
    fs::write(
        &seed,
        serde_json::to_vec(
            &json!({"projects": [{"id": "app", "target_framework": "net8.0",
        "language_version": "12.0", "sources": ["App.cs", "Helpers.cs"], "references": [],
        "reference_directories": [std::env::var("MEHSCAN_ROSLYN_NET8_REFS").unwrap()],
        "defines": [], "nullable": false, "allow_unsafe": false,
        "assets_file": assets, "assets_target": "net8.0"}]}),
        )
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &assets,
        serde_json::to_vec(&json!({"targets": {"net8.0": {}},
        "libraries": {}, "packageFolders": {}, "project": {"frameworks": {"net8.0": {}}}}))
        .unwrap(),
    )
    .unwrap();
    let run = |args: &[&str]| -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        if out.stdout.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&out.stdout).unwrap()
        }
    };
    let baseline = run(&["scan", root.to_str().unwrap(), "--format", "json"]);
    let prepared = run(&[
        "investigate",
        "csharp-context",
        root.to_str().unwrap(),
        "--context",
        seed.to_str().unwrap(),
        "--output",
        context.to_str().unwrap(),
    ]);
    assert_eq!(prepared["projects"][0]["resolved_compile_assets"], 0);
    let collection = run(&[
        "investigate",
        "csharp-semantic",
        root.to_str().unwrap(),
        "--context",
        context.to_str().unwrap(),
        "--backend",
        &backend,
        "--output",
        snapshot.to_str().unwrap(),
    ]);
    assert_eq!(collection["observations"], 4);
    assert_eq!(collection["requested_operands"], 4);
    assert_eq!(collection["covered_operands"], 4);
    assert_eq!(collection["uncovered_operands"], 0);
    let rejected = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "scan",
            root.to_str().unwrap(),
            "--csharp-semantic",
            snapshot.to_str().unwrap(),
            "--csharp-context",
            context.to_str().unwrap(),
            "--diff-mode",
            "impact",
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("requires full scan context"));
    let enriched = run(&[
        "scan",
        root.to_str().unwrap(),
        "--format",
        "json",
        "--csharp-semantic",
        snapshot.to_str().unwrap(),
        "--csharp-context",
        context.to_str().unwrap(),
    ]);
    assert_eq!(baseline["security_paths"], enriched["security_paths"]);
    assert_eq!(baseline["coverage"], enriched["coverage"]);
    assert_eq!(
        baseline,
        run(&["scan", root.to_str().unwrap(), "--format", "json"])
    );
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
        "--csharp-semantic",
        snapshot.to_str().unwrap(),
        "--csharp-context",
        context.to_str().unwrap(),
    ]);
    let listing = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--operand-kind",
        "semantic_definition",
    ]);
    let single_inventory = artifacts.join("single-inventory");
    let single = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .env("MEHSCAN_TRACE_PHASES", "1")
        .args([
            "investigate",
            "review-inventory",
            root.to_str().unwrap(),
            "--output",
            single_inventory.to_str().unwrap(),
            "--csharp-backend",
            &backend,
            "--csharp-context",
            context.to_str().unwrap(),
            "--timings",
            "true",
        ])
        .output()
        .unwrap();
    assert!(
        single.status.success(),
        "{}",
        String::from_utf8_lossy(&single.stderr)
    );
    let trace = String::from_utf8_lossy(&single.stderr);
    assert_eq!(
        trace
            .lines()
            .filter(|line| line.starts_with("mehscan_phase discovery "))
            .count(),
        1,
        "native inventory rescanned"
    );
    assert!(
        trace
            .lines()
            .any(|line| line.starts_with('{') && line.contains("native_milliseconds"))
    );
    let read = |dir: &std::path::Path| -> Value {
        serde_json::from_slice(&fs::read(dir.join("inventory.json")).unwrap()).unwrap()
    };
    assert_eq!(
        read(&inventory)["entries"],
        read(&single_inventory)["entries"]
    );
    assert_eq!(
        read(&inventory)["source_fingerprint"],
        read(&single_inventory)["source_fingerprint"]
    );
    assert_eq!(listing["matching_count"], 4);
    let id = listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["symbol"] == "Raw")
        .unwrap()["review_id"]
        .as_str()
        .unwrap();
    let manifest = run(&[
        "investigate",
        "review-bundles",
        root.to_str().unwrap(),
        "--inventory",
        inventory.to_str().unwrap(),
        "--review-ids",
        id,
        "--output",
        bundles.to_str().unwrap(),
    ]);
    let request = bundles
        .join("requests")
        .join(manifest["bundles"][0]["filename"].as_str().unwrap());
    let card = run(&[
        "investigate",
        "review-card",
        "--bundle",
        request.to_str().unwrap(),
        "--review-id",
        id,
    ]);
    assert!(
        card["operand_facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "semantic_definition")
    );
    let selected_snapshot = artifacts.join("selected-semantic.json");
    let selected = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .env("MEHSCAN_TRACE_PHASES", "1")
        .args([
            "investigate",
            "csharp-semantic",
            root.to_str().unwrap(),
            "--context",
            context.to_str().unwrap(),
            "--backend",
            &backend,
            "--inventory",
            inventory.to_str().unwrap(),
            "--evidence-ids",
            card["anchor"]["id"].as_str().unwrap(),
            "--output",
            selected_snapshot.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&selected.stderr).contains("mehscan_phase discovery "),
        "selected collection rescanned"
    );
    let selected_summary: Value = serde_json::from_slice(&selected.stdout).unwrap();
    assert_eq!(selected_summary["scan_reused"], true);
    assert_eq!(selected_summary["requested_operands"], 1);
    assert_eq!(
        selected_summary["selected_observations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let selected_facts: Value =
        serde_json::from_slice(&fs::read(&selected_snapshot).unwrap()).unwrap();
    let full_facts: Value = serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    assert_eq!(selected_facts["observations"].as_array().unwrap().len(), 1);
    assert_eq!(
        &selected_facts["observations"][0],
        full_facts["observations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["evidence_id"] == card["anchor"]["id"])
            .unwrap()
    );
    let unknown = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "csharp-semantic",
            root.to_str().unwrap(),
            "--context",
            context.to_str().unwrap(),
            "--backend",
            &backend,
            "--inventory",
            inventory.to_str().unwrap(),
            "--evidence-ids",
            "not-an-evidence-id",
            "--output",
            selected_snapshot.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown evidence ID"));
    let draft = artifacts.join("draft.json");
    let journals = artifacts.join("journals");
    fs::create_dir_all(&journals).unwrap();
    let response = bundles
        .join("responses")
        .join(manifest["bundles"][0]["filename"].as_str().unwrap());
    fs::write(
        &draft,
        serde_json::to_vec(&json!({"results":[{
            "review_id": id, "decision":"needs_review", "confidence":"low",
            "summary":"Contract test only: caller control is not established.",
            "checks":["Establish caller authority and reachable runtime effect."],
            "reason":"The caller authority and reachable runtime effect require review."
        }]}))
        .unwrap(),
    )
    .unwrap();
    run(&[
        "investigate",
        "review-bundle-finalize",
        "--bundle",
        request.to_str().unwrap(),
        "--draft",
        draft.to_str().unwrap(),
        "--journal-dir",
        journals.to_str().unwrap(),
        "--output",
        response.to_str().unwrap(),
        "--source-root",
        root.to_str().unwrap(),
    ]);
    let ledger = artifacts.join("ledger.json");
    run(&[
        "investigate",
        "review-ledger",
        "--inventory",
        inventory.to_str().unwrap(),
        "--history",
        artifacts.to_str().unwrap(),
        "--output",
        ledger.to_str().unwrap(),
    ]);
    let cache_path = inventory.join("scan-cache.json");
    let current_cache = fs::read(&cache_path).unwrap();
    let mut old_cache: Value = serde_json::from_slice(&current_cache).unwrap();
    old_cache["schema_version"] = json!("1");
    old_cache.as_object_mut().unwrap().remove("semantic_inputs");
    fs::write(&cache_path, serde_json::to_vec(&old_cache).unwrap()).unwrap();
    let rejected_old = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundles",
            root.to_str().unwrap(),
            "--inventory",
            inventory.to_str().unwrap(),
            "--review-ids",
            id,
            "--output",
            artifacts.join("old-chunk").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!rejected_old.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_old.stderr)
            .contains("unsupported review inventory version")
    );
    fs::write(cache_path, current_cache).unwrap();
    let original_request = fs::read(&request).unwrap();
    let mut altered: Value = serde_json::from_slice(&original_request).unwrap();
    altered["reviews"][0]["evidence"][0]["tags"]
        .as_array_mut()
        .unwrap()
        .push(json!("altered-after-binding"));
    fs::write(&request, serde_json::to_vec(&altered).unwrap()).unwrap();
    let rejected_history = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-ledger",
            "--inventory",
            inventory.to_str().unwrap(),
            "--history",
            artifacts.to_str().unwrap(),
            "--output",
            ledger.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!rejected_history.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_history.stderr)
            .contains("request changed after input binding")
    );
    fs::write(&request, original_request).unwrap();
    fs::write(&assets, b"changed graph").unwrap();
    let stale_cached = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundles",
            root.to_str().unwrap(),
            "--inventory",
            inventory.to_str().unwrap(),
            "--review-ids",
            id,
            "--output",
            artifacts.join("stale-chunk").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!stale_cached.status.success());
    assert!(String::from_utf8_lossy(&stale_cached.stderr).contains("input metadata is stale"));
    let stale = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "scan",
            root.to_str().unwrap(),
            "--csharp-semantic",
            snapshot.to_str().unwrap(),
            "--csharp-context",
            context.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("input metadata is stale"));
    // Fresh collection consumes source captures, not obsolete native facts.
    // Old bundle/history reuse above still rejects stale native metadata.
    fs::write(
        &assets,
        serde_json::to_vec(&json!({"targets":{"net8.0":{}},"libraries":{},
        "packageFolders":{},"project":{"frameworks":{"net8.0":{}}},"changed":true}))
        .unwrap(),
    )
    .unwrap();
    run(&[
        "investigate",
        "csharp-context",
        root.to_str().unwrap(),
        "--context",
        seed.to_str().unwrap(),
        "--output",
        context.to_str().unwrap(),
    ]);
    let fresh = run(&[
        "investigate",
        "csharp-semantic",
        root.to_str().unwrap(),
        "--context",
        context.to_str().unwrap(),
        "--backend",
        &backend,
        "--inventory",
        inventory.to_str().unwrap(),
        "--evidence-ids",
        card["anchor"]["id"].as_str().unwrap(),
        "--output",
        selected_snapshot.to_str().unwrap(),
    ]);
    assert_eq!(fresh["scan_reused"], true);
    assert_eq!(fresh["requested_operands"], 1);
    assert_eq!(fresh["covered_operands"], 1);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}
