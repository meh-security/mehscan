use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::Path, process::Command};

fn run(args: &[&str]) -> Value {
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
}

#[test]
fn shared_question_queue_and_sweep_preserve_exceptions_and_exact_source() {
    let root = std::env::temp_dir().join(format!("mehscan-sweep-{}", std::process::id()));
    let output = root.with_file_name(format!("mehscan-sweep-output-{}", std::process::id()));
    fs::create_dir_all(root.join("src")).unwrap();
    let source = r#"<?php
function esc_html($value) { return $value; }
function renderer($stored, $raw) {
    $raw = $_GET['raw'];
    // esc_html($stored) occurs before the real output.
    $unused = 'context';
    ?><p><?php echo esc_html($stored); ?></p>
    <script>let unsafe = "<?php echo esc_html($raw); ?>";</script>
    <p><?php echo esc_html($stored); ?></p>
    <div data-value=<?php echo esc_attr($raw); ?>></div>
    <p><?php echo esc_html($stored) . $raw; ?></p><?php
}
function first_include() { require APP_ROOT . '/' . $_GET['module']; }
function second_include() { require APP_ROOT . '/' . $_GET['plugin']; }
add_filter('esc_html', 'unsafe_callback');
"#;
    fs::write(root.join("src/view.php"), source).unwrap();
    let syntax = run(&[
        "investigate",
        "structural",
        root.to_str().unwrap(),
        "--language",
        "php",
        "--pattern",
        "echo $CONTENT;",
        "--path",
        "src/view.php",
    ]);
    assert!(
        !syntax["results"].as_array().unwrap().is_empty(),
        "PHP follow-up selector must work"
    );
    let callbacks = run(&[
        "investigate",
        "structural",
        root.to_str().unwrap(),
        "--language",
        "php",
        "--pattern",
        "add_filter('esc_html', $$$ARGS)",
        "--path",
        "src/view.php",
    ]);
    assert_eq!(
        callbacks["results"].as_array().unwrap().len(),
        1,
        "callback query must find real registrations"
    );
    let ambiguous = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "structural",
            root.to_str().unwrap(),
            "--language",
            "php",
            "--pattern",
            "echo $FIRST; echo $SECOND;",
            "--path",
            "src/view.php",
        ])
        .output()
        .unwrap();
    assert!(
        !ambiguous.status.success(),
        "must not silently query only the first statement"
    );
    for (name, language, contents) in [
        ("helper.c", "c", "void helper(char *raw) { sink(raw); }"),
        ("helper.cpp", "cpp", "void helper(char *raw) { sink(raw); }"),
        ("helper.rs", "rust", "fn helper(raw: &str) { sink(raw); }"),
    ] {
        fs::write(root.join("src").join(name), contents).unwrap();
        let path = format!("src/{name}");
        let matches = run(&[
            "investigate",
            "structural",
            root.to_str().unwrap(),
            "--language",
            language,
            "--pattern",
            "sink($VALUE);",
            "--path",
            &path,
        ]);
        assert_eq!(
            matches["results"].as_array().unwrap().len(),
            1,
            "missing {language} follow-up"
        );
    }
    let inventory = output.join("inventory");
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
    ]);
    let saved: Value =
        serde_json::from_slice(&fs::read(inventory.join("inventory.json")).unwrap()).unwrap();
    let queue = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--group-by",
        "contract",
    ]);
    assert_eq!(queue["matching_review_count"], saved["review_count"]);
    // Mixed raw output and the two request-selected code loaders have no
    // shared verified contract; they remain independent.
    assert_eq!(queue["ungrouped_review_count"], 3);
    let neighborhoods = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--group-by",
        "implementation",
        "--limit",
        "100",
    ]);
    assert_eq!(
        neighborhoods["matching_review_count"],
        saved["review_count"]
    );
    let first_page = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--group-by",
        "implementation",
        "--limit",
        "1",
    ]);
    assert_eq!(first_page["returned_count"], 1);
    assert_eq!(first_page["next_offset"], 1, "{first_page:#?}");
    assert_eq!(first_page["by_capability"], neighborhoods["by_capability"]);
    let counted: u64 = first_page["by_capability"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v["review_count"].as_u64().unwrap())
        .sum();
    assert_eq!(counted, saved["review_count"].as_u64().unwrap());
    assert_eq!(neighborhoods["next_offset"], Value::Null);
    let neighborhood_ids: Vec<_> = neighborhoods["groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["review_ids"].as_array().unwrap())
        .map(|id| id.as_str().unwrap())
        .collect();
    let saved_ids: BTreeSet<_> = saved["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["review_id"].as_str().unwrap())
        .collect();
    assert_eq!(neighborhood_ids.len(), saved_ids.len());
    assert_eq!(
        neighborhood_ids.iter().copied().collect::<BTreeSet<_>>(),
        saved_ids
    );
    assert!(
        neighborhoods["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["verified"] == false)
    );
    // Distinct code-loader functions remain separate, even with a common prefix.
    assert_eq!(
        neighborhoods["groups"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|g| matches!(
                g["symbol"].as_str(),
                Some("first_include" | "second_include")
            ))
            .count(),
        2
    );
    assert!(
        queue["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["verified"] == false)
    );
    let includes = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--contract",
        "configured_root_path:APP_ROOT",
    ]);
    assert_eq!(
        includes["matching_count"], 0,
        "a fixed prefix does not prove a shared selection contract"
    );
    let encoded = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--contract",
        "encoding_call:esc_html",
    ]);
    assert_eq!(encoded["matching_count"], 3); // Includes overridden helper and wrong script context.
    let reviewed_id = encoded["entries"][0]["review_id"].as_str().unwrap();
    let ledger = output.join("ledger.json");
    fs::write(&ledger, serde_json::to_vec(&json!({"schema_version":"2","source_fingerprint":saved["source_fingerprint"],"input_fingerprint":saved["input_fingerprint"],"inventory_count":saved["review_count"],"reviewed":{reviewed_id:"not_issue"},"conflicts":[]})).unwrap()).unwrap();
    let remaining = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--ledger",
        ledger.to_str().unwrap(),
        "--group-by",
        "contract",
        "--contract",
        "encoding_call:esc_html",
    ]);
    assert_eq!(remaining["matching_review_count"], 2);
    assert_eq!(remaining["groups"][0]["review_count"], 2);
    let remaining_implementation = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--ledger",
        ledger.to_str().unwrap(),
        "--group-by",
        "implementation",
        "--contract",
        "encoding_call:esc_html",
    ]);
    assert_eq!(remaining_implementation["matching_review_count"], 2);
    assert_eq!(remaining_implementation["groups"][0]["review_count"], 2);
    assert!(
        !remaining_implementation["groups"][0]["review_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == reviewed_id)
    );

    let chunk = output.join("chunk");
    let selected_ids = saved["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["review_id"].as_str().unwrap())
        .collect::<Vec<_>>()
        .join(",");
    let manifest = run(&[
        "investigate",
        "review-bundles",
        root.to_str().unwrap(),
        "--inventory",
        inventory.to_str().unwrap(),
        "--output",
        chunk.to_str().unwrap(),
        "--review-ids",
        &selected_ids,
    ]);
    let mut all_ids = BTreeSet::new();
    let mut merged = false;
    for bundle in manifest["bundles"].as_array().unwrap() {
        let request = chunk
            .join("requests")
            .join(bundle["filename"].as_str().unwrap());
        let sweep = run(&[
            "investigate",
            "review-sweep",
            "--bundle",
            request.to_str().unwrap(),
        ]);
        assert_eq!(sweep["bundle_fingerprint"], bundle["bundle_fingerprint"]);
        let ids: BTreeSet<_> = sweep["reviews"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["review_id"].as_str().unwrap().to_string())
            .collect();
        let expected: BTreeSet<_> = bundle["review_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids, expected);
        all_ids.extend(ids);
        let contexts = sweep["source_contexts"].as_array().unwrap();
        for context in contexts {
            if context["truncated"] == true {
                continue;
            }
            let start = context["location"]["start_line"].as_u64().unwrap() as usize;
            let end = context["location"]["end_line"].as_u64().unwrap() as usize;
            let expected = source
                .lines()
                .skip(start - 1)
                .take(end - start + 1)
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(
                context["excerpt"], expected,
                "incorrect citation coordinates"
            );
        }
        let mut original_bytes = 0;
        for card in sweep["reviews"].as_array().unwrap() {
            let original = run(&[
                "investigate",
                "review-card",
                "--bundle",
                request.to_str().unwrap(),
                "--review-id",
                card["review_id"].as_str().unwrap(),
            ]);
            assert_eq!(card["selected_anchor_id"], original["selected_anchor_id"]);
            assert_eq!(card["decision_facts"], original["decision_facts"]);
            let question = sweep["questions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|q| q["id"] == card["question_id"])
                .unwrap();
            for field in ["category", "playbook", "security_question", "relationship"] {
                assert_eq!(
                    question[field], original[field],
                    "lost question/control context"
                );
            }
            original_bytes += original["source_context"]["excerpt"]
                .as_str()
                .unwrap_or_default()
                .len();
            assert!(
                card["source_context_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|id| contexts.iter().any(|c| c["id"] == *id
                        && c["location"]["start_line"].as_u64()
                            <= card["anchor"]["location"]["start_line"].as_u64()
                        && c["location"]["end_line"].as_u64()
                            >= card["anchor"]["location"]["start_line"].as_u64()))
            );
        }
        let sweep_bytes: usize = contexts
            .iter()
            .map(|c| c["excerpt"].as_str().unwrap().len())
            .sum();
        merged |= sweep_bytes < original_bytes;
    }
    assert!(merged, "overlapping windows should be read once");
    assert_eq!(
        all_ids.len() as u64,
        saved["review_count"].as_u64().unwrap()
    );
    for path in [&root, &output] {
        fs::remove_dir_all(Path::new(path)).unwrap();
    }
}
