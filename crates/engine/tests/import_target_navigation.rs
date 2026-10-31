use std::fs;

#[test]
fn explicit_import_paths_disambiguate_names_without_inventing_dispatch() {
    let root =
        std::env::temp_dir().join(format!("mehscan-import-navigation-{}", std::process::id()));
    fs::create_dir_all(root.join("left")).unwrap();
    fs::create_dir_all(root.join("right")).unwrap();
    fs::write(
        root.join("left/guard.ts"),
        "export class Guard { check() { return false; } }",
    )
    .unwrap();
    fs::write(
        root.join("right/guard.ts"),
        "export class Guard { check() { return true; } }",
    )
    .unwrap();
    fs::write(root.join("app.ts"), "import { Guard as SelectedGuard } from './left/guard';\nimport { Missing } from './absent';\n// import { Guard } from './right/guard';\nconst text = \"import { Guard } from './right/guard'\";\n").unwrap();
    let result = mehscan_engine::investigation::get_import_targets(&root, "app.ts").unwrap();
    let value = serde_json::to_value(result).unwrap();
    let rows = value["results"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["source_path"], "left/guard.ts");
    assert_eq!(rows[0]["status"], "source");
    assert!(rows[0]["scope"].as_str().unwrap().contains("unproven"));
    assert_eq!(rows[1]["status"], "unresolved");
    assert!(rows[1]["source_path"].is_null());
    assert!(mehscan_engine::investigation::get_import_targets(&root, "../outside.ts").is_err());
    fs::remove_dir_all(root).unwrap();
}
