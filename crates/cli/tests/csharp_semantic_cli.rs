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
        serde_json::from_slice(&out.stdout).unwrap()
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
    assert_eq!(listing["matching_count"], 1);
    let id = listing["entries"][0]["review_id"].as_str().unwrap();
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
    fs::write(&assets, b"changed graph").unwrap();
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
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}
