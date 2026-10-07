use serde_json::{Value, json};
use std::{fs, path::PathBuf, process::Command};

#[test]
#[ignore = "requires Node and MEHSCAN_TYPESCRIPT_BACKEND / MEHSCAN_TYPESCRIPT_COMPILER"]
fn browser_value_selection_preserves_sensitive_requests_and_reopens_same_surface() {
    let root = std::env::temp_dir().join(format!("mehscan-browser-cli-{}", std::process::id()));
    let artifacts = root.with_extension("run");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&artifacts).unwrap();
    fs::write(root.join("browser.ts"), r#"
export function ordinary(url: string) { return fetch(url); }
export function head(url: string) { return fetch(url, {method: 'HEAD'}); }
export function bearer(url: string) { return fetch(url, {headers: {Authorization: 'Bearer token'}}); }
export function mutate(url: string) { return fetch(url, {method: 'POST'}); }
"#).unwrap();
    let context = artifacts.join("context.json");
    let inventory = artifacts.join("inventory");
    let bundles = artifacts.join("bundles");
    let backend = std::env::var("MEHSCAN_TYPESCRIPT_BACKEND").unwrap();
    fs::write(&context, serde_json::to_vec(&json!({"typescript_path":std::env::var("MEHSCAN_TYPESCRIPT_COMPILER").unwrap(),
        "projects":[{"id":"browser","runtime":"browser","sources":["browser.ts"],"compiler_options":{"target":"ES2022","module":"commonjs"}}]})).unwrap()).unwrap();
    let run = |args: &[&str]| -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
        "--typescript-context",
        context.to_str().unwrap(),
        "--typescript-backend",
        &backend,
    ]);
    let list = |mode: &str, extra: &[&str]| {
        let mut args = vec![
            "investigate",
            "review-inventory-list",
            "--inventory",
            inventory.to_str().unwrap(),
            "--selection",
            mode,
        ];
        args.extend_from_slice(extra);
        run(&args)
    };
    let all = list("all", &[]);
    let value = list("value", &[]);
    let deferred = list("deferred", &["--operand-kind", "browser_request_context"]);
    assert_eq!(all["matching_count"], 4);
    assert_eq!(value["matching_count"], 2);
    assert_eq!(deferred["matching_count"], 2);
    let overview: Value =
        serde_json::from_slice(&fs::read(inventory.join("overview.json")).unwrap()).unwrap();
    assert_eq!(overview["value_conditional_count"], 2);
    let bearer = value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["symbol"] == "bearer")
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
        bearer,
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
        bearer,
    ]);
    assert!(card["operand_facts"].as_array().unwrap().iter().any(|f| {
        f["kind"] == "browser_request_context"
            && f["remaining_checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == "request_options_require_review")
    }));
    let saved: Value =
        serde_json::from_slice(&fs::read(inventory.join("inventory.json")).unwrap()).unwrap();
    let ledger = artifacts.join("test-ledger.json");
    for decision in ["issue", "needs_review", "not_issue"] {
        fs::write(&ledger, serde_json::to_vec(&json!({"schema_version":"2","source_fingerprint":saved["source_fingerprint"],
            "input_fingerprint":saved["input_fingerprint"],"inventory_count":4,"reviewed":{bearer:decision},"conflicts":[]})).unwrap()).unwrap();
        let queue = list("value", &["--ledger", ledger.to_str().unwrap()]);
        assert_eq!(
            queue["reopened_count"],
            if decision == "not_issue" { 0 } else { 2 }
        );
        assert_eq!(queue["reviewed_count"], 1); // No synthetic verdict for ordinary siblings.
    }
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&artifacts).unwrap();
}

#[test]
#[ignore = "requires Node and MEHSCAN_TYPESCRIPT_BACKEND / MEHSCAN_TYPESCRIPT_COMPILER"]
fn compiler_collection_import_and_cached_cards_use_real_cli() {
    let root = std::env::temp_dir().join(format!("mehscan-typescript-cli-{}", std::process::id()));
    let artifacts = root.with_extension("run");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&artifacts).unwrap();
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typescript-semantic");
    for file in ["app.ts", "helpers.ts", "driver.ts"] {
        fs::copy(fixtures.join(file), root.join(file)).unwrap();
    }
    let context = artifacts.join("context.json");
    let snapshot = artifacts.join("semantic.json");
    let inventory = artifacts.join("inventory");
    let imported = artifacts.join("imported");
    let bundles = artifacts.join("bundles");
    let backend = std::env::var("MEHSCAN_TYPESCRIPT_BACKEND").unwrap();
    fs::write(
        &context,
        serde_json::to_vec(&json!({
            "typescript_path": std::env::var("MEHSCAN_TYPESCRIPT_COMPILER").unwrap(),
            "projects": [{"id": "web", "sources": ["app.ts", "helpers.ts", "driver.ts"],
                "compiler_options": {"target": "ES2022", "module": "commonjs", "strict": true}}]
        }))
        .unwrap(),
    )
    .unwrap();
    let run = |args: &[&str]| -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let baseline = run(&["scan", root.to_str().unwrap(), "--format", "json"]);
    let collection = run(&[
        "investigate",
        "typescript-semantic",
        root.to_str().unwrap(),
        "--context",
        context.to_str().unwrap(),
        "--backend",
        &backend,
        "--output",
        snapshot.to_str().unwrap(),
    ]);
    assert!(collection["covered_operands"].as_u64().unwrap() > 0);
    let enriched = run(&[
        "scan",
        root.to_str().unwrap(),
        "--format",
        "json",
        "--typescript-semantic",
        snapshot.to_str().unwrap(),
        "--typescript-context",
        context.to_str().unwrap(),
    ]);
    assert_eq!(baseline["security_paths"], enriched["security_paths"]);
    assert_eq!(baseline["coverage"], enriched["coverage"]);
    let ids = |scan: &Value| {
        scan["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&baseline), ids(&enriched));

    // A real wrapper fails on a second compiler launch: saved-card generation must use cached facts.
    let counter = artifacts.join("launch-count.txt");
    let wrapper = artifacts.join("once.mjs");
    let import_url = format!("file:///{}", backend.replace('\\', "/"));
    fs::write(&wrapper, format!(
        "import fs from 'node:fs';\nimport {{collect}} from {};\nconst count = {};\nif(fs.existsSync(count)) throw Error('compiler launched twice');\nfs.writeFileSync(count, '1');\nprocess.stdout.write(JSON.stringify(collect(JSON.parse(fs.readFileSync(0,'utf8')))));\n",
        serde_json::to_string(&import_url).unwrap(), serde_json::to_string(&counter).unwrap()
    )).unwrap();
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
        "--typescript-backend",
        wrapper.to_str().unwrap(),
        "--typescript-context",
        context.to_str().unwrap(),
    ]);
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        imported.to_str().unwrap(),
        "--typescript-semantic",
        snapshot.to_str().unwrap(),
        "--typescript-context",
        context.to_str().unwrap(),
    ]);
    let read_inventory = |dir: &std::path::Path| -> Value {
        serde_json::from_slice(&fs::read(dir.join("inventory.json")).unwrap()).unwrap()
    };
    assert_eq!(
        read_inventory(&inventory)["entries"],
        read_inventory(&imported)["entries"]
    );
    let listing = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--operand-kind",
        "semantic_definition",
    ]);
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
            .any(|f| f["kind"] == "semantic_definition" && f["location"]["path"] == "helpers.ts")
    );
    assert_eq!(fs::read_to_string(&counter).unwrap(), "1");
    fs::write(
        root.join("helpers.ts"),
        "export function makeQuery(v: string) { return v; }\n",
    )
    .unwrap();
    let stale = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundles",
            root.to_str().unwrap(),
            "--inventory",
            inventory.to_str().unwrap(),
            "--review-ids",
            id,
            "--output",
            bundles.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("stale"));
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}
