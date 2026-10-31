use std::{fs, process::Command};

#[test]
fn bounded_export_query_is_read_only_and_journaled() {
    let temp = std::env::temp_dir().join(format!("mehscan-export-cli-{}", std::process::id()));
    let root = temp.join("source");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("index.ts"),
        "export { check as guard } from './leaf';",
    )
    .unwrap();
    fs::write(
        root.join("leaf.ts"),
        "export function check() { return false; }",
    )
    .unwrap();
    let journal = temp.join("queries.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "export-target",
            root.to_str().unwrap(),
            "--path",
            "index.ts",
            "--name",
            "guard",
            "--journal",
            journal.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["operation"], "get_export_target");
    assert_eq!(response["results"]["candidate"]["path"], "leaf.ts");
    let records = fs::read_to_string(journal).unwrap();
    assert_eq!(records.lines().count(), 1);
    let record: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
    assert_eq!(record["operation"], "export-target");
    assert_eq!(record["output"], response);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    fs::remove_dir_all(temp).unwrap();
}
