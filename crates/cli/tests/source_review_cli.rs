use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "mehscan-source-review-cli-{}-{nonce}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&base).unwrap();
    fs::create_dir(base.join("source")).unwrap();
    base
}

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(args)
        .output()
        .unwrap()
}

fn run(args: &[&str]) -> Value {
    let output = invoke(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        Value::Null
    } else {
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

fn read_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn cleanup(base: &Path) {
    assert!(
        base.canonicalize()
            .unwrap()
            .starts_with(std::env::temp_dir().canonicalize().unwrap())
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn admitted_source_questions_export_complete_inventory_and_reuse_finalized_history() {
    let base = fixture();
    let source = base.join("source");
    let original = base.join("original");
    let history = base.join("run");
    let inventory = history.join("inventory");
    fs::write(
        source.join("decoder.py"),
        "def decode(data):\n    count = int.from_bytes(data[:4], 'little')\n    return bytearray(count)\n",
    )
    .unwrap();
    let source_path = source.to_str().unwrap();
    run(&[
        "investigate",
        "review-inventory",
        source_path,
        "--repository-key",
        "fixture-decoder",
        "--output",
        original.to_str().unwrap(),
    ]);
    let original_overview = read_json(original.join("overview.json"));
    let plan = run(&[
        "investigate",
        "source-review-plan",
        source_path,
        "--inventory",
        original.to_str().unwrap(),
    ]);
    let assignment = plan["assignments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|assignment| {
            assignment["windows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|window| window["path"] == "decoder.py")
        })
        .unwrap();
    let citation = json!({
        "path":"decoder.py", "start_line":3, "end_line":3,
        "quote":"return bytearray(count)"
    });
    let admission = json!({
        "plan":plan,
        "inspected":[],
        "proposals":[{
            "key":"decoded-allocation", "assignment_id":assignment["id"],
            "capability":"deserialization", "cwes":["CWE-789"],
            "question":"Is the decoded allocation length bounded before allocation?",
            "mechanism":"A decoded count is passed directly to bytearray.",
            "consequence":"An uncontrolled count can request disproportionate storage.",
            "priority":"value", "anchor":citation, "evidence":[citation]
        }]
    });
    let admission_path = base.join("admission.json");
    fs::write(&admission_path, serde_json::to_vec(&admission).unwrap()).unwrap();
    let admitted = run(&[
        "investigate",
        "source-review-admit",
        source_path,
        "--inventory",
        original.to_str().unwrap(),
        "--input",
        admission_path.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
    ]);
    let review_id = admitted["mapping"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    let overview = read_json(inventory.join("overview.json"));
    let summary = read_json(inventory.join("inventory.json"));
    assert!(inventory.join("scan-cache.json").is_file());
    assert_eq!(overview["input_fingerprint"], admitted["input_fingerprint"]);
    assert_eq!(overview["input_fingerprint"], summary["input_fingerprint"]);
    assert_ne!(
        overview["input_fingerprint"],
        original_overview["input_fingerprint"]
    );
    assert_eq!(
        overview["review_count"].as_u64().unwrap(),
        original_overview["review_count"].as_u64().unwrap() + 1
    );
    assert_eq!(overview["by_capability"]["deserialization"], 1);
    assert_eq!(
        overview["native_identity"]["repository"]["repository_key"],
        "fixture-decoder"
    );
    let chunk = history.join("chunk-1");
    let manifest = run(&[
        "investigate",
        "review-bundles",
        source_path,
        "--inventory",
        inventory.to_str().unwrap(),
        "--review-ids",
        review_id,
        "--output",
        chunk.to_str().unwrap(),
    ]);
    let filename = manifest["bundles"][0]["filename"].as_str().unwrap();
    let request = chunk.join("requests").join(filename);
    let response = chunk.join("responses").join(filename);
    let journals = history.join("journals");
    fs::create_dir_all(&journals).unwrap();
    let draft = base.join("draft.json");
    fs::write(
        &draft,
        serde_json::to_vec(&json!({"results":[{
            "review_id":review_id, "decision":"needs_review", "confidence":"medium",
            "summary":"Decoded allocation limits require caller evidence.",
            "reason":"The allocation uses the decoded count; caller limits are not supplied.",
            "checks":["Which caller bounds the decoded count before this allocation?"],
            "evidence":[{"path":"decoder.py", "start_line":3, "end_line":3}]
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
        source_path,
    ]);
    let ledger_path = base.join("ledger.json");
    let ledger_args = [
        "investigate",
        "review-ledger",
        "--inventory",
        inventory.to_str().unwrap(),
        "--history",
        history.to_str().unwrap(),
        "--output",
        ledger_path.to_str().unwrap(),
    ];
    run(&ledger_args);
    let ledger = read_json(&ledger_path);
    assert_eq!(ledger["reviewed"][review_id], "needs_review");
    assert_eq!(ledger["input_fingerprint"], admitted["input_fingerprint"]);
    assert_eq!(ledger["inventory_count"], overview["review_count"]);
    assert!(ledger["conflicts"].as_array().unwrap().is_empty());

    // An old overview must not make augmented source questions reusable.
    let mut stale = overview;
    stale["input_fingerprint"] = original_overview["input_fingerprint"].clone();
    fs::write(
        inventory.join("overview.json"),
        serde_json::to_vec(&stale).unwrap(),
    )
    .unwrap();
    let failed = invoke(&ledger_args);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("different review inputs"));
    assert_eq!(read_json(&ledger_path), ledger);
    cleanup(&base);
}

#[test]
fn source_plan_retains_parser_failed_source_and_scopes_its_limitations() {
    let base = fixture();
    let source = base.join("source");
    fs::write(
        source.join("Broken.cs"),
        "public class Broken { public void Read( {\n",
    )
    .unwrap();
    fs::write(
        source.join("healthy.py"),
        "def read(value):\n    return value\n",
    )
    .unwrap();
    let inventory = base.join("inventory");
    run(&[
        "investigate",
        "review-inventory",
        source.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
    ]);
    assert_eq!(
        read_json(inventory.join("overview.json"))["coverage"]["parse_failed"],
        1
    );
    let plan = run(&[
        "investigate",
        "source-review-plan",
        source.to_str().unwrap(),
        "--inventory",
        inventory.to_str().unwrap(),
    ]);
    assert!(plan["assignments"].as_array().unwrap().iter().any(|a| {
        a["windows"].as_array().unwrap().iter().any(|w| {
            w["path"] == "Broken.cs" && w["text"].as_str().unwrap().contains("public class Broken")
        })
    }));
    assert!(plan["limitations"].as_array().unwrap().iter().any(|l| {
        l.as_str().unwrap().contains("Broken.cs") && l.as_str().unwrap().contains("exact source")
    }));
    let selected = base.join("selected.txt");
    fs::write(&selected, "healthy.py\n").unwrap();
    let scoped_inventory = base.join("scoped-inventory");
    run(&[
        "investigate",
        "review-inventory",
        source.to_str().unwrap(),
        "--files-from",
        selected.to_str().unwrap(),
        "--output",
        scoped_inventory.to_str().unwrap(),
    ]);
    let scoped = run(&[
        "investigate",
        "source-review-plan",
        source.to_str().unwrap(),
        "--inventory",
        scoped_inventory.to_str().unwrap(),
    ]);
    assert!(scoped["limitations"].as_array().unwrap().is_empty());
    assert!(scoped["assignments"].as_array().unwrap().iter().all(|a| {
        a["windows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|w| w["path"] == "healthy.py")
    }));
    cleanup(&base);
}
