use mehscan_engine::{csharp_context, csharp_semantic};
use serde_json::{Value, json};
use std::path::PathBuf;

struct Fixture {
    root: PathBuf,
    seed: PathBuf,
    output: PathBuf,
    assets: PathBuf,
}
impl Fixture {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-assets-{label}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("packages/example/1.0/ref/net8.0")).unwrap();
        std::fs::write(root.join("App.cs"), "class App {}").unwrap();
        std::fs::write(root.join("App.csproj"), "<Project />").unwrap();
        std::fs::write(
            root.join("packages/example/1.0/ref/net8.0/Example.dll"),
            "metadata location fixture, not native API proof",
        )
        .unwrap();
        let assets = root.join("project.assets.json");
        let seed = root.join("seed.json");
        let output = root.join("context.json");
        std::fs::write(&assets, serde_json::to_vec(&json!({"targets": {
            "net8.0": {"Example/1.0": {"type": "package", "compile": {"ref/net8.0/Example.dll": {}, "ref/net8.0/_._": {}},
                "runtime": {"lib/net8.0/RuntimeOnly.dll": {}}, "build": {"build/task.targets": {}}, "analyzers": {"analyzers/Analyzer.dll": {}}}},
            "net10.0": {"Other/2.0": {"type": "package", "compile": {"lib/net10.0/Other.dll": {}}}}},
            "libraries": {"Example/1.0": {"path": "example/1.0"}},
            "project": {"frameworks": {"net8.0": {}}}, "packageFolders": {root.join("absent-cache").to_str().unwrap(): {}}
        })).unwrap()).unwrap();
        std::fs::write(&seed, serde_json::to_vec(&json!({"context_files": [root.join("App.csproj")], "projects": [{
            "id": "app", "target_framework": "net8.0", "language_version": "12.0", "sources": ["App.cs"],
            "references": [], "reference_directories": [], "defines": [], "assets_file": assets,
            "assets_target": "net8.0", "package_roots": [root.join("packages")]}]})).unwrap()).unwrap();
        Self {
            root,
            seed,
            output,
            assets,
        }
    }
    fn read(&self, path: &PathBuf) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }
    fn write(&self, path: &PathBuf, value: &Value) {
        std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }
    fn prepare(&self) -> Result<Value, mehscan_engine::EngineError> {
        csharp_context::prepare(&self.root, &self.seed, &self.output)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn selects_only_exact_compile_assets_and_records_context_inputs() {
    let f = Fixture::new("compile");
    let summary = f.prepare().unwrap();
    assert_eq!(summary["projects"][0]["resolved_compile_assets"], 1);
    assert_eq!(summary["projects"][0]["unresolved_references"], json!([]));
    let prepared = f.read(&f.output);
    let refs = prepared["projects"][0]["references"].as_array().unwrap();
    assert_eq!(refs.len(), 1);
    assert!(refs[0].as_str().unwrap().ends_with("Example.dll"));
    assert_eq!(prepared["input_files"].as_array().unwrap().len(), 3);
    assert!(prepared["projects"][0].get("assets_file").is_none());
}

#[test]
fn explicit_source_links_replace_only_matching_project_placeholders() {
    let f = Fixture::new("source-links");
    std::fs::write(f.root.join("Helpers.cs"), "public class Helper {}").unwrap();
    let mut seed = f.read(&f.seed);
    let mut child = seed["projects"][0].clone();
    child["id"] = json!("src/Project.csproj");
    child["sources"] = json!(["Helpers.cs"]);
    seed["projects"][0]["project_references"] = json!(["src/Project.csproj"]);
    seed["projects"].as_array_mut().unwrap().push(child);
    f.write(&f.seed, &seed);
    let mut assets = f.read(&f.assets);
    assets["targets"]["net8.0"]["Project/1.0"] =
        json!({"type":"project", "compile":{"bin/placeholder/Project.dll":{}}});
    assets["targets"]["net8.0"]["OtherProject/1.0"] =
        json!({"type":"project", "compile":{"bin/placeholder/OtherProject.dll":{}}});
    f.write(&f.assets, &assets);
    let summary = f.prepare().unwrap();
    assert_eq!(summary["projects"][0]["resolved_source_projects"], 1);
    assert_eq!(
        summary["projects"][0]["unresolved_references"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        f.read(&f.output)["projects"][0]["project_references"],
        json!(["src/Project.csproj"])
    );
    seed["projects"][0]["project_references"] = json!(["not-supplied"]);
    f.write(&f.seed, &seed);
    assert!(f.prepare().is_err());
}

#[test]
fn missing_versions_and_project_placeholders_stay_gaps_without_runtime_fallback() {
    let f = Fixture::new("missing");
    std::fs::remove_file(f.root.join("packages/example/1.0/ref/net8.0/Example.dll")).unwrap();
    std::fs::create_dir_all(f.root.join("packages/example/2.0/ref/net8.0")).unwrap();
    std::fs::write(
        f.root.join("packages/example/2.0/ref/net8.0/Example.dll"),
        "newer version must not be selected",
    )
    .unwrap();
    let mut assets = f.read(&f.assets);
    assets["targets"]["net8.0"]["Project/1.0"] =
        json!({"type": "project", "compile": {"bin/placeholder/Project.dll": {}}});
    assets["logs"] = json!([{"level": "Error", "code": "NU1101"}]);
    f.write(&f.assets, &assets);
    let summary = f.prepare().unwrap();
    assert_eq!(summary["projects"][0]["resolved_compile_assets"], 0);
    assert_eq!(
        summary["projects"][0]["unresolved_references"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(f.read(&f.output)["projects"][0]["references"], json!([]));
}

#[test]
fn rejects_wrong_missing_targets_and_package_version_or_path_mismatches() {
    let f = Fixture::new("targets");
    let seed = f.read(&f.seed);
    for target in ["net10.0", "net8.0/linux-x64"] {
        let mut changed = seed.clone();
        changed["projects"][0]["assets_target"] = json!(target);
        f.write(&f.seed, &changed);
        assert!(f.prepare().is_err());
        assert!(!f.output.exists());
    }
    f.write(&f.seed, &seed);
    let assets = f.read(&f.assets);
    for path in ["example/2.0", "../outside", "/absolute"] {
        let mut changed = assets.clone();
        changed["libraries"]["Example/1.0"]["path"] = json!(path);
        f.write(&f.assets, &changed);
        assert!(f.prepare().is_err());
    }
    let mut changed = assets;
    changed["targets"]["net8.0"]["Example/1.0"]["compile"] = json!({"../Outside.dll": {}});
    f.write(&f.assets, &changed);
    assert!(
        f.prepare()
            .unwrap_err()
            .0
            .contains("Invalid package/compile")
    );
}

#[test]
fn metadata_changes_block_collection_before_backend_launch() {
    let f = Fixture::new("staleness");
    let scan = mehscan_engine::scan_path(&f.root).unwrap();
    for input in [&f.assets, &f.seed, &f.root.join("App.csproj")] {
        f.prepare().unwrap();
        let original = std::fs::read(input).unwrap();
        std::fs::write(input, b"changed input").unwrap();
        let error = csharp_semantic::collect(
            &f.root,
            &f.output,
            &f.root.join("nonexistent-backend"),
            &scan,
        )
        .unwrap_err();
        assert!(error.0.contains("input metadata is stale"), "{}", error.0);
        std::fs::write(input, original).unwrap();
    }
}

#[test]
fn prepared_contexts_and_input_overwrites_are_rejected() {
    let f = Fixture::new("outputs");
    let original = std::fs::read(&f.seed).unwrap();
    assert!(
        csharp_context::prepare(&f.root, &f.seed, &f.seed)
            .unwrap_err()
            .0
            .contains("overwrite")
    );
    assert_eq!(original, std::fs::read(&f.seed).unwrap());
    f.prepare().unwrap();
    assert!(
        csharp_context::prepare(&f.root, &f.output, &f.root.join("second.json"))
            .unwrap_err()
            .0
            .contains("original context seed")
    );
}
