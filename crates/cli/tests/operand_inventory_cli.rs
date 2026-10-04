use std::{fs, process::Command};

#[test]
fn prepared_use_filter_survives_saved_inventory_and_selected_packaging() {
    let root = std::env::temp_dir().join(format!("mehscan-jvm-use-cli-{}", std::process::id()));
    let artifacts = root.with_file_name(format!("mehscan-jvm-use-cli-run-{}", std::process::id()));
    let inventory = artifacts.join("inventory");
    let bundles = artifacts.join("bundles");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("Review.java"), "import java.sql.Connection;\nclass Review {\nvoid query(Connection c, String q) throws Exception {\nvar st = c.prepareStatement(q);\nst.executeQuery();\n}\n}\n").unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()
    };
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
    ]);
    let listing = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--operand-kind",
        "prepared_statement_use",
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
    let fact = card["operand_facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["kind"] == "prepared_statement_use")
        .unwrap();
    assert_eq!(fact["location"]["start"]["line"], 5);
    assert_eq!(fact["value"], "st");
    assert_eq!(fact["role"], "prepared_statement_execution_context");
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&artifacts).unwrap();
}

#[test]
fn csharp_constructor_and_reassignment_facts_survive_saved_inventory_and_cards() {
    let root =
        std::env::temp_dir().join(format!("mehscan-csharp-operand-cli-{}", std::process::id()));
    let artifacts = root.with_file_name(format!(
        "mehscan-csharp-operand-cli-run-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("Review.cs"), "using Dapper;\nusing System.Data.Common;\nclass Review {\nobject Fixed(DbConnection db, string value) {\nvar cmd = new CommandDefinition(\"SELECT @value\", new {value});\nreturn db.Query(cmd);\n}\nobject Changed(DbConnection db, string value) {\nvar cmd = new CommandDefinition(\"SELECT @value\", new {value});\ncmd = new CommandDefinition(value);\nreturn db.Query(cmd);\n}\n}\n").unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        artifacts.to_str().unwrap(),
    ]);
    let inventory = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        artifacts.to_str().unwrap(),
        "--operand-kind",
        "query_structure",
    ]);
    assert_eq!(inventory["matching_count"], 1);
    assert_eq!(inventory["entries"][0]["symbol"], "Fixed");
    let changed = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        artifacts.to_str().unwrap(),
        "--operand-kind",
        "operand_boundary",
    ]);
    assert_eq!(changed["matching_count"], 1);
    let id = changed["entries"][0]["review_id"].as_str().unwrap();
    let chunk = artifacts.join("chunk");
    let manifest = run(&[
        "investigate",
        "review-bundles",
        root.to_str().unwrap(),
        "--inventory",
        artifacts.to_str().unwrap(),
        "--review-ids",
        id,
        "--output",
        chunk.to_str().unwrap(),
    ]);
    let request = chunk
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
    assert_eq!(card["anchor"]["captures"]["query"], "cmd");
    assert!(
        card["operand_facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "operand_boundary" && f["location"]["start"]["line"] == 10)
    );
    assert_eq!(
        card["suggested_lookups"][0]["arguments"]["path"],
        "Review.cs"
    );
    let value = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        artifacts.to_str().unwrap(),
        "--selection",
        "value",
    ]);
    assert_eq!(value["matching_count"], 2);
    assert_eq!(value["deferred_count"], 0);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}

#[test]
fn node_alias_facts_support_precise_followup_and_reopening() {
    let root =
        std::env::temp_dir().join(format!("mehscan-node-operand-cli-{}", std::process::id()));
    let artifacts = root.with_file_name(format!(
        "mehscan-node-operand-cli-run-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("app.js"), "const {Client} = require('pg');\nconst cp = require('node:child_process');\nconst client = new Client();\nfunction fixed(value) { const config = {text: 'SELECT $1', values: [value]}; return client.query(config); }\nfunction composed(value) { const config = {text: 'SELECT ' + value}; return client.query(config); }\nfunction launch(value) {\nconst opts = {shell: false};\nopts.shell = true;\nreturn cp.execFile('tool', [value], opts);\n}\n").unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        artifacts.to_str().unwrap(),
    ]);
    let list = |extra: &[&str]| {
        let mut args = vec![
            "investigate",
            "review-inventory-list",
            "--inventory",
            artifacts.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        run(&args)
    };
    let all = list(&[]);
    let entries = all["entries"].as_array().unwrap();
    let id = |name: &str| {
        entries.iter().find(|e| e["symbol"] == name).unwrap()["review_id"]
            .as_str()
            .unwrap()
    };
    let fixed = id("fixed");
    assert_eq!(
        list(&["--selection", "deferred"])["entries"][0]["review_id"],
        fixed
    );
    for kind in [
        "local_operand_origin",
        "operand_boundary",
        "query_structure",
    ] {
        assert!(
            list(&["--operand-kind", kind])["matching_count"]
                .as_u64()
                .unwrap()
                > 0
        );
    }
    let chunk = artifacts.join("chunk");
    let manifest = run(&[
        "investigate",
        "review-bundles",
        root.to_str().unwrap(),
        "--inventory",
        artifacts.to_str().unwrap(),
        "--review-ids",
        id("launch"),
        "--output",
        chunk.to_str().unwrap(),
    ]);
    let request = chunk
        .join("requests")
        .join(manifest["bundles"][0]["filename"].as_str().unwrap());
    let card = run(&[
        "investigate",
        "review-card",
        "--bundle",
        request.to_str().unwrap(),
        "--review-id",
        id("launch"),
    ]);
    assert!(
        card["operand_facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "operand_boundary" && f["location"]["start"]["line"] == 8)
    );
    assert_eq!(card["suggested_lookups"][0]["arguments"]["path"], "app.js");
    let start = card["suggested_lookups"][0]["arguments"]["start-line"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let end = card["suggested_lookups"][0]["arguments"]["end-line"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(start <= 8 && end >= 8);
    assert!(
        card["security_question"]
            .as_str()
            .unwrap()
            .contains("effective process options"),
        "{card}"
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(artifacts.join("inventory.json")).unwrap()).unwrap();
    let ledger = artifacts.join("ledger.json");
    for decision in ["issue", "needs_review", "not_issue"] {
        fs::write(&ledger, serde_json::to_vec(&serde_json::json!({"schema_version": "2", "source_fingerprint": saved["source_fingerprint"], "input_fingerprint": saved["input_fingerprint"], "inventory_count": entries.len(), "reviewed": {id("composed"): decision}, "conflicts": []})).unwrap()).unwrap();
        let queue = list(&["--selection", "value", "--ledger", ledger.to_str().unwrap()]);
        assert_eq!(
            queue["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["review_id"] == fixed),
            decision != "not_issue"
        );
        assert_eq!(
            queue["reopened_count"],
            if decision == "not_issue" { 0 } else { 1 }
        );
    }
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}

#[test]
fn filters_compact_operand_facts_and_exposes_them_on_selected_cards() {
    let root = std::env::temp_dir().join(format!("mehscan-operand-cli-{}", std::process::id()));
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/review.php"), "<?php\nfunction fixed() { require __DIR__ . '/helper.php'; }\nfunction encoded($stored) { echo esc_html($stored); }\nfunction dynamic() { require $_GET['page']; }\nfunction numeric() { echo (int) $_GET['raw']; }\n").unwrap();
    fs::write(root.join("src/helper.php"), "<?php return 'helper';").unwrap();
    let artifacts = root.with_file_name(format!(
        "mehscan-operand-cli-artifacts-{}",
        std::process::id()
    ));
    let inventory_dir = artifacts.join("inventory");
    let run = artifacts.join("chunk");
    let inventory = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-inventory",
            root.to_str().unwrap(),
            "--output",
            inventory_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(inventory.status.success(), "{:?}", inventory.stderr);
    let overview: serde_json::Value =
        serde_json::from_slice(&fs::read(inventory_dir.join("overview.json")).unwrap()).unwrap();
    assert_eq!(overview["by_operand_fact"]["fixed_code_relative_path"], 1);
    assert_eq!(overview["by_operand_fact"]["encoding_call"], 1);
    assert_eq!(overview["deterministic_operand_closures"], 1);
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(inventory_dir.join("inventory.json")).unwrap()).unwrap();
    let closed = &saved["admission_audit"]["closed_operands"][0];
    assert_eq!(closed["rule_id"], "php-html-output");
    assert_eq!(closed["disposition"], "safely_suppressed");
    assert_eq!(closed["operand_fact"]["kind"], "numeric_output");
    assert_eq!(saved["review_count"], 3);
    assert_eq!(overview["value_deferred_count"], 2);
    assert_eq!(overview["value_active_count"], 1);
    assert_eq!(overview["value_conditional_count"], 1);
    assert_eq!(
        overview["value_deferrals_by_reason"]["ordinary_php_sink_inventory"],
        1
    );
    let value = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-inventory-list",
            "--inventory",
            inventory_dir.to_str().unwrap(),
            "--selection",
            "value",
        ])
        .output()
        .unwrap();
    assert!(value.status.success(), "{:?}", value.stderr);
    let value: serde_json::Value = serde_json::from_slice(&value.stdout).unwrap();
    assert_eq!(value["scope_count"], 3);
    assert_eq!(value["matching_count"], 1);
    assert_eq!(value["deferred_count"], 2);
    let mut fixed_id = String::new();
    for kind in ["fixed_code_relative_path", "encoding_call", "unclassified"] {
        let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args([
                "investigate",
                "review-inventory-list",
                "--inventory",
                inventory_dir.to_str().unwrap(),
                "--operand-kind",
                kind,
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        let listed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(listed["matching_count"], 1, "{kind}: {listed}");
        if kind == "fixed_code_relative_path" {
            fixed_id = listed["entries"][0]["review_id"].as_str().unwrap().into();
            assert_eq!(
                listed["entries"][0]["value_hint"]["target"],
                "src/helper.php"
            );
        }
        if kind == "unclassified" {
            assert_eq!(listed["entries"][0]["symbol"], "dynamic");
        }
    }
    let invalid = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-inventory-list",
            "--inventory",
            inventory_dir.to_str().unwrap(),
            "--operand-kind",
            "safe",
        ])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    let bundles = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundles",
            root.to_str().unwrap(),
            "--inventory",
            inventory_dir.to_str().unwrap(),
            "--review-ids",
            &fixed_id,
            "--output",
            run.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(bundles.status.success(), "{:?}", bundles.stderr);
    let manifest: serde_json::Value = serde_json::from_slice(&bundles.stdout).unwrap();
    let request = run
        .join("requests")
        .join(manifest["bundles"][0]["filename"].as_str().unwrap());
    let card = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-card",
            "--bundle",
            request.to_str().unwrap(),
            "--review-id",
            &fixed_id,
        ])
        .output()
        .unwrap();
    assert!(card.status.success(), "{:?}", card.stderr);
    let card: serde_json::Value = serde_json::from_slice(&card.stdout).unwrap();
    assert_eq!(card["operand_facts"][0]["value"], "src/helper.php");
    assert_eq!(card["suggested_lookups"][0]["operation"], "source");
    assert_eq!(
        card["suggested_lookups"][0]["arguments"]["path"],
        "src/helper.php"
    );
    assert_eq!(
        card["operand_facts"][0]["remaining_checks"][0],
        "target_existence_and_content_trust"
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}
