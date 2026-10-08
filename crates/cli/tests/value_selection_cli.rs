use std::{fs, process::Command};

#[test]
fn ordinary_owned_directory_creation_is_deferred_without_losing_writes_or_inputs() {
    let root =
        std::env::temp_dir().join(format!("mehscan-directory-priority-{}", std::process::id()));
    let artifacts = root.with_extension("inventory");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("app.js"), "const fs=require('fs');\nfunction mkdir(path){fs.mkdirSync(path);}\nfunction write(path,data){fs.writeFileSync(path,data);}\nfunction endpoint(req,res){fs.mkdirSync(req.query.path);}").unwrap();
    fs::write(root.join("app.php"), "<?php function make_dir($path){mkdir($path,0755);} function write_file($path,$data){file_put_contents($path,$data);} function endpoint(){mkdir($_GET['path'],0755);}").unwrap();
    fs::write(root.join("app.ts"), "import * as fs from 'fs';\nfunction make(path:string){fs.mkdirSync(path);}\nfunction write(path:string,data:string){fs.writeFileSync(path,data);}").unwrap();
    fs::write(root.join("App.java"), "import java.nio.file.Files; import java.nio.file.Path; class App { void make(Path path) throws Exception { Files.createDirectories(path); } void write(Path path,byte[] data) throws Exception { Files.write(path,data); } }").unwrap();
    fs::write(root.join("app.go"), "package app\nimport \"os\"\nfunc makeDir(path string){os.MkdirAll(path,0755)}\nfunc write(path string,data []byte){os.WriteFile(path,data,0600)}").unwrap();
    fs::write(
        root.join("lookalike.js"),
        "const fs={mkdirSync(path){return eval(path)}}; function custom(path){fs.mkdirSync(path);}",
    )
    .unwrap();
    fs::write(root.join("lookalike.php"), "<?php namespace Custom; function mkdir($path,$mode){return eval($path);} function custom($path){mkdir($path,0755);}").unwrap();
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
    let list = |selection| {
        run(&[
            "investigate",
            "review-inventory-list",
            "--inventory",
            artifacts.to_str().unwrap(),
            "--selection",
            selection,
            "--limit",
            "100",
        ])
    };
    let deferred = list("deferred");
    let entries = deferred["entries"].as_array().unwrap();
    for path in ["app.js", "app.ts", "app.php", "App.java", "app.go"] {
        assert!(
            entries.iter().any(|e| e["path"] == path
                && e["value_hint"]["reason"] == "ordinary_directory_creation_inventory"),
            "missing {path}: {deferred}"
        );
    }
    assert!(
        entries
            .iter()
            .all(|e| !e["path"].as_str().unwrap().starts_with("lookalike")),
        "{deferred}"
    );
    let value = list("value");
    let active = value["entries"].as_array().unwrap();
    for path in ["app.js", "app.ts", "app.php", "App.java", "app.go"] {
        assert!(
            active
                .iter()
                .any(|e| e["path"] == path && e["capability"] == "filesystem_write"),
            "lost write {path}: {value}"
        );
    }
    for path in ["app.js", "app.php"] {
        assert!(
            active
                .iter()
                .any(|e| e["path"] == path && e["symbol"] == "endpoint"),
            "lost connected directory {path}: {value}"
        );
    }
    let all = list("all");
    assert_eq!(
        all["matching_count"].as_u64().unwrap(),
        value["matching_count"].as_u64().unwrap() + deferred["matching_count"].as_u64().unwrap()
    );
    // Deferral retains exact IDs and can reopen after an unresolved/unsafe
    // result on the same file/rule surface. No safe verdict was manufactured.
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(artifacts.join("inventory.json")).unwrap()).unwrap();
    let representative = active
        .iter()
        .find(|e| e["path"] == "app.php" && e["symbol"] == "write_file")
        .unwrap()["review_id"]
        .as_str()
        .unwrap();
    let ledger = artifacts.join("ledger.json");
    fs::write(&ledger, serde_json::to_vec(&serde_json::json!({"schema_version":"2","source_fingerprint":saved["source_fingerprint"],"input_fingerprint":saved["input_fingerprint"],"inventory_count":saved["entries"].as_array().unwrap().len(),"reviewed":{representative:"needs_review"},"conflicts":[]})).unwrap()).unwrap();
    let reopened = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        artifacts.to_str().unwrap(),
        "--selection",
        "value",
        "--ledger",
        ledger.to_str().unwrap(),
        "--limit",
        "100",
    ]);
    assert!(
        reopened["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "app.php" && e["symbol"] == "make_dir"),
        "{reopened}"
    );
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&artifacts).unwrap();
}

#[test]
fn build_scope_defers_ordinary_sinks_and_preserves_runtime_and_connected_work() {
    let root = std::env::temp_dir().join(format!("mehscan-build-scope-{}", std::process::id()));
    let output = root.with_extension("inventory");
    fs::create_dir_all(root.join("tools")).unwrap();
    fs::write(
        root.join("package.json"),
        r#"{"main":"app.js","scripts":{"build":"node tools/build.js","start":"node app.js"}}"#,
    )
    .unwrap();
    fs::write(root.join("tools/build.js"), "require('./render'); const fs=require('fs'); function build(path,data) { fs.writeFileSync(path,data); }").unwrap();
    fs::write(root.join("tools/render.js"), "const fs=require('fs'); module.exports=function render(path) { return fs.readFileSync(path); };").unwrap();
    fs::write(
        root.join("app.js"),
        "const fs=require('fs'); function read(path) { return fs.readFileSync(path); }",
    )
    .unwrap();
    let inventory = |output: &std::path::Path| {
        let command = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args([
                "investigate",
                "review-inventory",
                root.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            command.status.success(),
            "{}",
            String::from_utf8_lossy(&command.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(output.join("inventory.json")).unwrap(),
        )
        .unwrap()
    };
    let saved = inventory(&output);
    let entries = saved["entries"].as_array().unwrap();
    for path in ["tools/build.js", "tools/render.js"] {
        assert!(
            entries.iter().any(|e| e["path"] == path
                && e["value_hint"]["reason"] == "package_build_tooling_inventory"),
            "missing build hint for {path}: {saved}"
        );
    }
    assert!(
        entries
            .iter()
            .any(|e| e["path"] == "app.js" && e["value_hint"].is_null())
    );
    let listed = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-inventory-list",
            "--inventory",
            output.to_str().unwrap(),
            "--selection",
            "value",
        ])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let value: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(
        value["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["path"] == "app.js")
    );
    fs::write(root.join("app.js"), "require('./tools/render'); const fs=require('fs'); function read(path) { return fs.readFileSync(path); }").unwrap();
    let shared = inventory(&root.with_extension("shared-inventory"));
    assert!(
        shared["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "tools/render.js" && e["value_hint"].is_null())
    );
    fs::write(root.join("tools/build.js"), "const express=require('express'); const fs=require('fs'); const app=express(); app.get('/file',(req,res)=>res.send(fs.readFileSync(req.query.path))); ").unwrap();
    let strong = inventory(&root.with_extension("strong-inventory"));
    assert!(
        strong["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "tools/build.js"
                && e["evidence_strength"] != "sink"
                && e["value_hint"].is_null()),
        "connected build work must remain active: {strong}"
    );
}

#[test]
#[ignore = "requires Roslyn backend and real .NET/ASP.NET 10 refs"]
fn shared_destinations_and_helpers_keep_exceptions_and_reopen_exact_dependents() {
    let root =
        std::env::temp_dir().join(format!("mehscan-csharp-producers-{}", std::process::id()));
    let artifacts = root.with_extension("run");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&artifacts).unwrap();
    fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/roslyn-output/App.cs"),
        root.join("App.cs"),
    )
    .unwrap();
    let context = artifacts.join("context.json");
    fs::write(&context, serde_json::to_vec(&serde_json::json!({"projects": [{
        "id": "app", "target_framework": "net10.0", "language_version": "14.0", "sources": ["App.cs"],
        "references": [], "reference_directories": [std::env::var("MEHSCAN_ROSLYN_NET10_REFS").unwrap(), std::env::var("MEHSCAN_ROSLYN_ASPNET10_REFS").unwrap()], "defines": []
    }]})).unwrap()).unwrap();
    let run = |args: &[&str]| -> serde_json::Value {
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
    let inventory = artifacts.join("inventory");
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
        "--csharp-backend",
        &std::env::var("MEHSCAN_ROSLYN_BACKEND").unwrap(),
        "--csharp-context",
        context.to_str().unwrap(),
    ]);
    let deferred = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--selection",
        "deferred",
    ]);
    assert_eq!(deferred["matching_count"], 7, "{deferred}");
    let value = run(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory.to_str().unwrap(),
        "--selection",
        "value",
    ]);
    for name in [
        "RawSuffix",
        "ReplacedUrl",
        "DifferentHook",
        "DifferentRoot",
        "DeleteBypass",
        "DeleteInlineUnknownOption",
        "DeleteInlineModified",
        "DeleteOther",
        "DeleteReplaced",
        "Read",
    ] {
        assert!(
            value["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["symbol"] == name),
            "lost exception: {name}"
        );
    }
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(inventory.join("inventory.json")).unwrap()).unwrap();
    let ledger = artifacts.join("ledger.json");
    for child in deferred["entries"].as_array().unwrap() {
        let representative = child["value_hint"]["depends_on"].as_str().unwrap();
        let dependent_count = deferred["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["value_hint"]["depends_on"] == representative)
            .count();
        for verdict in ["issue", "needs_review", "not_issue"] {
            fs::write(&ledger, serde_json::to_vec(&serde_json::json!({
                "schema_version": "2", "source_fingerprint": saved["source_fingerprint"], "input_fingerprint": saved["input_fingerprint"],
                "inventory_count": saved["entries"].as_array().unwrap().len(), "reviewed": {representative: verdict}, "conflicts": []
            })).unwrap()).unwrap();
            let queue = run(&[
                "investigate",
                "review-inventory-list",
                "--inventory",
                inventory.to_str().unwrap(),
                "--selection",
                "value",
                "--ledger",
                ledger.to_str().unwrap(),
            ]);
            assert_eq!(
                queue["reopened_count"],
                if verdict == "not_issue" {
                    0
                } else {
                    dependent_count
                }
            );
            assert_eq!(
                queue["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["review_id"] == child["review_id"]),
                verdict != "not_issue"
            );
        }
        let requests = artifacts.join(format!("bundle-{}", child["review_id"].as_str().unwrap()));
        let bundle = run(&[
            "investigate",
            "review-bundles",
            root.to_str().unwrap(),
            "--inventory",
            inventory.to_str().unwrap(),
            "--review-ids",
            child["review_id"].as_str().unwrap(),
            "--output",
            requests.to_str().unwrap(),
        ]);
        assert_eq!(bundle["review_count"], 1);
    }
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&artifacts).unwrap();
}

#[test]
#[ignore = "requires Roslyn helper and real .NET 10 refs"]
fn compiler_bound_shared_filesystem_slots_keep_exact_ids_and_reopen() {
    let root = std::env::temp_dir().join(format!("mehscan-csharp-value-{}", std::process::id()));
    let artifacts =
        std::env::temp_dir().join(format!("mehscan-csharp-value-run-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&artifacts).unwrap();
    fs::write(
        root.join("App.cs"),
        r#"using System.IO;
class App {
 void Shared(string path) { File.Delete(path); File.Delete(path); File.ReadAllText(path); }
 void Mutable(string path, string other) { File.Delete(path); path = other; File.Delete(path); }
 void Ref(string path) { File.Delete(path); Change(ref path); File.Delete(path); }
 void Change(ref string path) { path = "changed"; }
 void Other(string path) { File.Delete(path); }
 void MakeDirectory(string path) { Directory.CreateDirectory(path); }
 void RemoveDirectory(string path) { Directory.Delete(path); }
 void MixedDirectory(string path) { Directory.CreateDirectory(path); Directory.Delete(path); }
 void ListDirectory(string path) { Directory.GetFiles(path); }
 void ReadFile(string path) { File.ReadAllText(path); }
 void MixedRead(string path) { Directory.GetFiles(path); File.ReadAllText(path); }
 void RecursiveList(string path) { Directory.GetFiles(path,"*",SearchOption.AllDirectories); }
}"#,
    )
    .unwrap();
    let context = artifacts.join("context.json");
    fs::write(&context, serde_json::to_vec(&serde_json::json!({"projects": [{
        "id": "app", "target_framework": "net10.0", "language_version": "14.0", "sources": ["App.cs"],
        "references": [], "reference_directories": [std::env::var("MEHSCAN_ROSLYN_NET10_REFS").unwrap()], "defines": []
    }]})).unwrap()).unwrap();
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
    let semantic = artifacts.join("semantic.json");
    run(&[
        "investigate",
        "csharp-semantic",
        root.to_str().unwrap(),
        "--context",
        context.to_str().unwrap(),
        "--backend",
        &std::env::var("MEHSCAN_ROSLYN_BACKEND").unwrap(),
        "--output",
        semantic.to_str().unwrap(),
    ]);
    let inventory = artifacts.join("inventory");
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
        "--csharp-semantic",
        semantic.to_str().unwrap(),
        "--csharp-context",
        context.to_str().unwrap(),
    ]);
    let list = |selection: &str, extra: &[&str]| {
        let mut args = vec![
            "investigate",
            "review-inventory-list",
            "--inventory",
            inventory.to_str().unwrap(),
            "--selection",
            selection,
        ];
        args.extend_from_slice(extra);
        run(&args)
    };
    let all = list("all", &[]);
    let deferred = list("deferred", &[]);
    assert_eq!(deferred["matching_count"], 5, "{deferred}");
    assert!(
        deferred["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["symbol"] == "ListDirectory"
                && e["value_hint"]["reason"] == "ordinary_directory_listing_inventory"),
        "{deferred}"
    );
    let child = deferred["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["symbol"] == "Shared")
        .unwrap();
    assert!(
        deferred["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["symbol"] == "MakeDirectory"
                && e["value_hint"]["reason"] == "ordinary_directory_creation_inventory")
    );
    assert_eq!(child["symbol"], "Shared");
    assert_eq!(
        child["value_hint"]["reason"],
        "shared_csharp_filesystem_selection"
    );
    let representative = child["value_hint"]["depends_on"].as_str().unwrap();
    let value = list("value", &[]);
    assert_eq!(
        all["matching_count"].as_u64().unwrap(),
        value["matching_count"].as_u64().unwrap() + 5
    );
    for symbol in [
        "Mutable",
        "Ref",
        "Other",
        "RemoveDirectory",
        "MixedDirectory",
        "ReadFile",
        "MixedRead",
        "RecursiveList",
    ] {
        assert!(
            value["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["symbol"] == symbol)
        );
    }
    assert!(
        value["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["symbol"] == "MixedRead"
                && e["operand_facts"]
                    .as_array()
                    .is_some_and(
                        |facts| facts.iter().any(|f| f["kind"] == "semantic_identity"
                            && f["value"]
                                .as_str()
                                .is_some_and(|v| v.starts_with("System.IO.File.ReadAllText(")))
                    )),
        "content read must not depend on low-value listing: {value}"
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(inventory.join("inventory.json")).unwrap()).unwrap();
    let ledger = artifacts.join("ledger.json");
    for verdict in ["issue", "needs_review", "not_issue"] {
        fs::write(&ledger, serde_json::to_vec(&serde_json::json!({
            "schema_version": "2", "source_fingerprint": saved["source_fingerprint"], "input_fingerprint": saved["input_fingerprint"],
            "inventory_count": saved["entries"].as_array().unwrap().len(), "reviewed": {representative: verdict}, "conflicts": []
        })).unwrap()).unwrap();
        let queue = list("value", &["--ledger", ledger.to_str().unwrap()]);
        assert_eq!(
            queue["reopened_count"],
            if verdict == "not_issue" { 0 } else { 3 }
        );
        assert_eq!(queue["reviewed_count"], 1);
        assert_eq!(
            queue["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["review_id"] == child["review_id"]),
            verdict != "not_issue"
        );
    }
    // Reject malformed declaration identity rather than grouping arbitrary slots.
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(&semantic).unwrap()).unwrap();
    let fact = snapshot["observations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .flat_map(|o| o["facts"].as_array_mut().unwrap())
        .find(|f| f["kind"] == "immutable_filesystem_operand")
        .unwrap();
    fact["value"] = serde_json::json!("unbound-slot");
    fs::write(&semantic, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-inventory",
            root.to_str().unwrap(),
            "--output",
            artifacts.join("rejected").to_str().unwrap(),
            "--csharp-semantic",
            semantic.to_str().unwrap(),
            "--csharp-context",
            context.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}

#[test]
fn source_defaults_and_shared_questions_preserve_gaps_and_reopen_dependents() {
    let root = std::env::temp_dir().join(format!("mehscan-value-questions-{}", std::process::id()));
    let artifacts = std::env::temp_dir().join(format!(
        "mehscan-value-questions-run-{}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("src/uploads")).unwrap();
    fs::write(
        root.join("src/constants.php"),
        r#"<?php
if (!defined('APP_ROOT')) { define('APP_ROOT', __DIR__ . '/'); }
const LIBRARY = 'helper.php';
define('CONFLICT_ROOT', __DIR__ . '/');
define('CONFLICT_ROOT', $_GET['root']);
define('DYNAMIC_ROOT', $_GET['root']);
define('CYCLE_ROOT', CYCLE_ROOT);
define('BAD_SIGNATURE', __DIR__ . '/');
define('BAD_SIGNATURE', $_GET['root'], true);
define('__CODE_ROOT__', dirname(__FILE__) . '/');
"#,
    )
    .unwrap();
    fs::write(root.join("src/helper.php"), "<?php return true;").unwrap();
    fs::write(root.join("src/uploads/item.php"), "<?php return true;").unwrap();
    fs::write(
        root.join("src/loaders.php"),
        r#"<?php
function source_default() { require APP_ROOT . LIBRARY; }
function conflict() { require CONFLICT_ROOT . 'helper.php'; }
function dynamic() { require DYNAMIC_ROOT . 'helper.php'; }
function cycle() { require CYCLE_ROOT . 'helper.php'; }
function missing() { require APP_ROOT . 'missing.php'; }
function upload() { require APP_ROOT . 'uploads/item.php'; }
function traversal() { require APP_ROOT . '../../../outside.php'; }
function bad_signature() { require BAD_SIGNATURE . 'helper.php'; }
function magic_like_name() { require __CODE_ROOT__ . 'helper.php'; }
"#,
    )
    .unwrap();
    fs::write(
        root.join("src/views.php"),
        r#"<?php function esc_html($x) { return $x; }
function views($a, $b, $raw) { ?>
<p><?php echo esc_html($a); ?></p>
<p><?php echo esc_html($b); ?></p>
<script><?php echo esc_html($raw); ?></script>
<script><?php echo esc_html($b); ?></script>
<script><?php echo $raw; ?></script>
<p onclick="<?php echo $raw; ?>">x</p>
<style><?php echo esc_html($raw); ?></style>
<textarea><?php echo esc_html($raw); ?></textarea>
<p title=<?php echo esc_html($raw); ?>>x</p>
<p onclick="<?php echo esc_html($raw); ?>">x</p>
<iframe srcdoc="<?php echo esc_html($raw); ?>"></iframe>
<a href="<?php echo esc_html($raw); ?>">x</a>
<a href="<?php echo esc_html($b); ?>">x</a>
<svg><a xlink:href="<?php echo esc_html($raw); ?>">x</a></svg>
<svg><a xlink:href="<?php echo esc_html($b); ?>">x</a></svg>
<p><?php echo esc_html($a) . $raw; ?></p>
<p><?php echo $raw; ?></p>
<p data-note=">" title="<?php echo esc_html($a); ?>">x</p>
<?php }
"#,
    )
    .unwrap();
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
    let list = |selection: &str, extra: &[&str]| {
        let mut args = vec![
            "investigate",
            "review-inventory-list",
            "--inventory",
            artifacts.to_str().unwrap(),
            "--selection",
            selection,
            "--limit",
            "200",
        ];
        args.extend_from_slice(extra);
        run(&args)
    };
    let all = list("all", &[]);
    let value = list("value", &[]);
    let deferred = list("deferred", &[]);
    assert_eq!(deferred["matching_count"], 5, "{deferred}");
    assert_eq!(
        all["matching_count"].as_u64().unwrap(),
        value["matching_count"].as_u64().unwrap() + 5
    );
    let entries = deferred["entries"].as_array().unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry["symbol"] == "source_default"
                && entry["value_hint"]["reason"] == "source_default_repository_include")
    );
    let repeated = entries
        .iter()
        .find(|entry| entry["value_hint"]["reason"] == "shared_php_encoding_question")
        .unwrap();
    let representative = repeated["value_hint"]["depends_on"].as_str().unwrap();
    assert_eq!(
        value["dependency_review_ids"],
        serde_json::json!([representative])
    );
    let values = value["entries"].as_array().unwrap();
    for symbol in [
        "conflict",
        "dynamic",
        "cycle",
        "missing",
        "upload",
        "traversal",
        "bad_signature",
    ] {
        assert!(
            values.iter().any(|entry| entry["symbol"] == symbol),
            "lost {symbol}"
        );
    }
    // A no-op encoder, wrong contexts and raw/mixed output cannot become safe
    // through a name match. Unconnected raw/mixed output is conditional surface
    // inventory; dangerous observed contexts stay individually active.
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry["symbol"] == "views")
            .count(),
        3
    );
    let title = values
        .iter()
        .find(|entry| {
            entry["operand_facts"].as_array().is_some_and(|facts| {
                facts
                    .iter()
                    .any(|fact| fact["value"] == "html_attribute:title:\"")
            })
        })
        .unwrap();
    assert_eq!(title["symbol"], "views");
    let filtered = list("value", &["--path-prefix", "src/views.php"]);
    assert_eq!(
        filtered["dependency_review_ids"],
        serde_json::json!([representative])
    );
    let inventory: serde_json::Value =
        serde_json::from_slice(&fs::read(artifacts.join("inventory.json")).unwrap()).unwrap();
    let ledger_path = artifacts.join("ledger.json");
    for decision in ["issue", "needs_review", "not_issue"] {
        fs::write(
            &ledger_path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": "2", "source_fingerprint": inventory["source_fingerprint"],
                "input_fingerprint": inventory["input_fingerprint"],
                "inventory_count": inventory["entries"].as_array().unwrap().len(),
                "reviewed": {representative: decision}, "conflicts": []
            }))
            .unwrap(),
        )
        .unwrap();
        let queue = list("value", &["--ledger", ledger_path.to_str().unwrap()]);
        let opened = decision != "not_issue";
        assert_eq!(queue["reopened_count"], if opened { 3 } else { 0 });
        assert_eq!(
            queue["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["review_id"] == repeated["review_id"]),
            opened
        );
        // No verdict is generated for a dependent, including after not_issue.
        assert_eq!(queue["reviewed_count"], 1);
    }
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}

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
function helper_selected() { require choose_file(); }
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
    assert_eq!(deferred["matching_count"], 4, "{deferred}");
    let fixed = deferred["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["symbol"] == "fixed")
        .unwrap();
    assert_eq!(fixed["value_hint"]["reason"], "fixed_repository_include");
    assert_eq!(
        all["matching_count"].as_u64().unwrap(),
        value["matching_count"].as_u64().unwrap() + 4
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
        "dynamic",
        "helper_selected",
        "disclosure",
        "raw_sql",
        "execute",
    ] {
        assert!(symbols.contains(&symbol), "lost {symbol}: {value}");
    }
    for symbol in ["root_config", "stored_output", "encoded_output"] {
        assert!(
            deferred["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["symbol"] == symbol
                    && entry["value_hint"]["reason"] == "ordinary_php_sink_inventory")
        );
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
