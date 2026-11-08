use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn reviewer_notes_embed_source_reject_stale_inputs_and_do_not_change_inventory() {
    let root = std::env::temp_dir().join(format!("mehscan-facts-{}", std::process::id()));
    let artifacts = root.with_extension("run");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&artifacts).unwrap();
    fs::write(
        root.join("App.php"),
        "<?php\nfunction render($s) { ?><script>let value=\"<?php echo htmlspecialchars($s); ?>\";</script><?php }\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args(args)
            .output()
            .unwrap()
    };
    let inventory = artifacts.join("inventory");
    assert!(
        run(&[
            "investigate",
            "review-inventory",
            root.to_str().unwrap(),
            "--output",
            inventory.to_str().unwrap()
        ])
        .status
        .success()
    );
    let before = fs::read(inventory.join("inventory.json")).unwrap();
    let queue = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--group-by",
        "contract",
    ]);
    let queue: Value = serde_json::from_slice(&queue.stdout).unwrap();
    let key = queue["groups"][0]["contract"].as_str().unwrap();
    let notes = artifacts.join("notes.json");
    let saved = artifacts.join("facts.json");
    fs::write(&notes, serde_json::to_vec(&json!({"facts":[{"contract":key,"statement":"Calls htmlspecialchars on the supplied value.","citations":[{"path":"App.php","start_line":2,"end_line":2}],"remaining_checks":["output context","options"]}]})).unwrap()).unwrap();
    let record = run(&[
        "investigate",
        "review-facts",
        root.to_str().unwrap(),
        "--inventory",
        inventory.to_str().unwrap(),
        "--notes",
        notes.to_str().unwrap(),
        "--output",
        saved.to_str().unwrap(),
    ]);
    assert!(
        record.status.success(),
        "{}",
        String::from_utf8_lossy(&record.stderr)
    );
    let reuse = || {
        run(&[
            "investigate",
            "review-facts",
            root.to_str().unwrap(),
            "--inventory",
            inventory.to_str().unwrap(),
            "--facts",
            saved.to_str().unwrap(),
            "--contract",
            key,
        ])
    };
    let current = reuse();
    assert!(current.status.success());
    let current: Value = serde_json::from_slice(&current.stdout).unwrap();
    assert!(
        current["facts"][0]["citations"][0]["excerpt"]
            .as_str()
            .unwrap()
            .contains("htmlspecialchars")
    );
    assert_eq!(current["origin"], "reviewer_source_note");
    assert_eq!(before, fs::read(inventory.join("inventory.json")).unwrap());
    let original = fs::read(&saved).unwrap();
    let mut stale: Value = serde_json::from_slice(&original).unwrap();
    stale["input_fingerprint"] = json!("old-inputs");
    fs::write(&saved, serde_json::to_vec(&stale).unwrap()).unwrap();
    assert!(!reuse().status.success());
    fs::write(&saved, &original).unwrap();
    let mut altered: Value = serde_json::from_slice(&original).unwrap();
    altered["facts"][0]["citations"][0]["excerpt"] = json!("invented safe source");
    fs::write(&saved, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(!reuse().status.success());
    fs::write(&saved, &original).unwrap();
    fs::write(
        root.join("App.php"),
        "<?php\nfunction render($s) { echo $s; }\n",
    )
    .unwrap();
    assert!(!reuse().status.success());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}

#[test]
fn cited_source_contract_can_be_reused_without_native_candidates() {
    let artifacts =
        std::env::temp_dir().join(format!("mehscan-source-facts-{}", std::process::id()));
    let root = artifacts.join("source");
    fs::create_dir_all(&root).unwrap();
    let helper = root.join("lib.rs");
    let original = "pub fn fits(bytes: usize, limit: usize) -> bool { bytes <= limit }\n";
    fs::write(&helper, original).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args(args)
            .output()
            .unwrap()
    };
    let inventory = artifacts.join("inventory");
    let scan = |output: &std::path::Path| {
        let result = run(&[
            "investigate",
            "review-inventory",
            root.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert!(result.status.success(), "{:?}", result.stderr);
        let summary: Value =
            serde_json::from_slice(&fs::read(output.join("inventory.json")).unwrap()).unwrap();
        assert_eq!(summary["review_count"], 0);
    };
    scan(&inventory);
    let notes = artifacts.join("notes.json");
    let saved = artifacts.join("facts.json");
    let record = |key| {
        fs::write(
            &notes,
            serde_json::to_vec(&json!({"facts":[{
                "contract": key,
                "statement": "The helper accepts byte counts at or below its supplied limit.",
                "citations": [{"path":"lib.rs","start_line":1,"end_line":1}],
                "remaining_checks": ["Which limit does each caller supply?"]
            }]}))
            .unwrap(),
        )
        .unwrap();
        run(&[
            "investigate",
            "review-facts",
            root.to_str().unwrap(),
            "--inventory",
            inventory.to_str().unwrap(),
            "--notes",
            notes.to_str().unwrap(),
            "--output",
            saved.to_str().unwrap(),
        ])
    };
    assert!(!record("source:lib.rs:1-2").status.success());
    let key = "source:lib.rs:1-1";
    let recorded = record(key);
    assert!(recorded.status.success(), "{:?}", recorded.stderr);
    let reuse = |from: &std::path::Path| {
        run(&[
            "investigate",
            "review-facts",
            root.to_str().unwrap(),
            "--inventory",
            from.to_str().unwrap(),
            "--facts",
            saved.to_str().unwrap(),
            "--contract",
            key,
        ])
    };
    let current = reuse(&inventory);
    assert!(current.status.success(), "{:?}", current.stderr);
    let result: Value = serde_json::from_slice(&current.stdout).unwrap();
    assert_eq!(
        result["facts"][0]["citations"][0]["excerpt"],
        original.trim()
    );
    assert_eq!(
        result["facts"][0]["remaining_checks"],
        json!(["Which limit does each caller supply?"])
    );

    // Changing only a caller still invalidates the fact across snapshots.
    fs::write(root.join("caller.rs"), "pub fn budget() -> usize { 128 }\n").unwrap();
    assert!(!reuse(&inventory).status.success());
    let updated = artifacts.join("updated");
    scan(&updated);
    let stale = reuse(&updated);
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("stale source or scanner inputs"));
    fs::remove_dir_all(artifacts).unwrap();
}
