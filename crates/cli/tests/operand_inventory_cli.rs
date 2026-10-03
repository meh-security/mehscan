use std::{fs, process::Command};

#[test]
fn filters_compact_operand_facts_and_exposes_them_on_selected_cards() {
    let root = std::env::temp_dir().join(format!("mehscan-operand-cli-{}", std::process::id()));
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/review.php"), "<?php\nfunction fixed() { require __DIR__ . '/helper.php'; }\nfunction encoded($stored) { echo esc_html($stored); }\nfunction dynamic() { require $_GET['page']; }\n").unwrap();
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
