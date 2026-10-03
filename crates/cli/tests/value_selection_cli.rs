use std::{fs, process::Command};

#[test]
fn value_defers_fixed_code_but_preserves_writers_missing_targets_and_dangerous_operations() {
    let root = std::env::temp_dir().join(format!("mehscan-value-source-{}", std::process::id()));
    let artifacts = std::env::temp_dir().join(format!("mehscan-value-run-{}", std::process::id()));
    fs::create_dir_all(root.join("src/uploads")).unwrap();
    fs::create_dir_all(root.join("src/generated")).unwrap();
    fs::write(
        root.join("src/main.php"),
        r#"<?php
function fixed() { require __DIR__ . '/helper.php'; }
function missing() { require __DIR__ . '/missing.php'; }
function writable() { require __DIR__ . '/uploads/item.php'; }
function generated() { require __DIR__ . '/generated/item.php'; }
function named_writer() { require __DIR__ . '/edited.php'; }
function root_config() { require BASE_PATH . '/helper.php'; }
function dynamic() { require $_GET['page']; }
function edit($content) { file_put_contents(__DIR__ . '/EDITED.php', $content); }
function disclosure() { readfile($_GET['file']); }
function stored_output($stored) { echo $stored; }
function encoded_output($stored) { echo esc_html($stored); }
"#,
    )
    .unwrap();
    // Deferring the include must never defer the included file's own sinks.
    fs::write(root.join("src/helper.php"), "<?php function raw_sql($sql) { mysqli_query($db, $sql); } function execute($cmd) { system($cmd); }").unwrap();
    for path in [
        "src/edited.php",
        "src/uploads/item.php",
        "src/generated/item.php",
    ] {
        fs::write(root.join(path), "<?php return true;").unwrap();
    }
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        artifacts.to_str().unwrap(),
    ]);
    let list = |selection: &str, extra: &[&str]| {
        let mut args = vec![
            "investigate",
            "review-inventory-list",
            "--inventory",
            artifacts.to_str().unwrap(),
            "--selection",
            selection,
        ];
        args.extend_from_slice(extra);
        run(&args)
    };
    let all = list("all", &[]);
    let value = list("value", &[]);
    let deferred = list("deferred", &[]);
    assert_eq!(deferred["matching_count"], 1, "{deferred}");
    assert_eq!(deferred["entries"][0]["symbol"], "fixed");
    assert_eq!(
        deferred["entries"][0]["value_hint"]["reason"],
        "fixed_repository_include"
    );
    assert_eq!(
        all["matching_count"].as_u64().unwrap(),
        value["matching_count"].as_u64().unwrap() + 1
    );
    let symbols: Vec<_> = value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["symbol"].as_str())
        .collect();
    for symbol in [
        "missing",
        "writable",
        "generated",
        "named_writer",
        "root_config",
        "dynamic",
        "disclosure",
        "stored_output",
        "encoded_output",
        "raw_sql",
        "execute",
    ] {
        assert!(symbols.contains(&symbol), "lost {symbol}: {value}");
    }
    let grouped = list(
        "value",
        &[
            "--group-by",
            "contract",
            "--operand-kind",
            "fixed_code_relative_path",
        ],
    );
    assert_eq!(grouped["scope_count"], 5);
    assert_eq!(grouped["matching_review_count"], 4);
    assert_eq!(grouped["deferred_count"], 1);
    let filtered = list("deferred", &["--path-prefix", "src/helper.php"]);
    assert_eq!(filtered["matching_count"], 0);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}
