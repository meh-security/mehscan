use serde_json::Value;
use std::{path::PathBuf, process::Command};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/razor-frontend")
}
fn scan(extra: &[&str]) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(["scan", fixture().to_str().unwrap(), "--format", "json"])
        .args(extra)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
fn razor_is_opt_in_and_backend_failure_retains_truthful_markup_coverage() {
    let baseline = scan(&[]);
    assert!(!baseline["evidence"].as_array().unwrap().iter().any(|e| {
        e["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "razor-sdk-source-projection")
    }));
    let failed = scan(&[
        "--razor-backend",
        "missing-backend",
        "--razor-sdk",
        "missing-sdk",
    ]);
    assert_eq!(baseline["evidence"], failed["evidence"]);
    assert!(failed["diagnostics"].as_array().unwrap().iter().any(|d| {
        d["message"]
            .as_str()
            .unwrap()
            .contains("markup-only coverage retained")
    }));
    let invalid = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(["scan", "--razor-sdk", "sdk"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
}

#[test]
#[ignore = "requires MEHSCAN_RAZOR_BACKEND and MEHSCAN_RAZOR_SDK (official SDK), .NET helper runtime"]
fn actual_sdk_projection_reuses_rules_with_original_locations_and_inventory() {
    let backend = std::env::var("MEHSCAN_RAZOR_BACKEND").unwrap();
    let sdk = std::env::var("MEHSCAN_RAZOR_SDK").unwrap();
    let result = scan(&["--razor-backend", &backend, "--razor-sdk", &sdk]);
    let repeated = scan(&["--razor-backend", &backend, "--razor-sdk", &sdk]);
    assert_eq!(result["evidence"], repeated["evidence"]);
    assert!(!result["evidence"].as_array().unwrap().iter().any(|e| {
        e["captures"].as_object().is_some_and(|c| {
            c.values()
                .any(|v| v["text"].as_str().is_some_and(|s| s.contains("quotedOnly")))
        })
    }));
    let projected: Vec<_> = result["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["tags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t == "razor-sdk-source-projection")
        })
        .collect();
    let calls: Vec<_> = projected
        .iter()
        .filter(|e| e["rule_id"] == "csharp-dynamic-code")
        .collect();
    assert_eq!(
        calls.len(),
        5,
        "diagnostics={} projected={projected:#?}",
        result["diagnostics"]
    );
    for e in projected {
        let source =
            std::fs::read_to_string(fixture().join(e["location"]["path"].as_str().unwrap()))
                .unwrap();
        for capture in e["captures"].as_object().unwrap().values() {
            let start = capture["location"]["start"]["byte_offset"]
                .as_u64()
                .unwrap() as usize;
            let end = capture["location"]["end"]["byte_offset"].as_u64().unwrap() as usize;
            assert_eq!(capture["text"].as_str().unwrap(), &source[start..end]);
            assert_eq!(
                capture["location"]["start"]["line"].as_u64().unwrap() as usize,
                source[..start].bytes().filter(|b| *b == b'\n').count() + 1
            );
        }
        assert!(!e["context"]["operand_facts"].as_array().unwrap().is_empty());
    }
    assert!(
        !result["security_paths"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|p| p["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["location"]["path"].as_str().unwrap().ends_with(".razor")))
    );
    let output =
        std::env::temp_dir().join(format!("mehscan-razor-inventory-{}", std::process::id()));
    let inventory = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-inventory",
            fixture().to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--razor-backend",
            &backend,
            "--razor-sdk",
            &sdk,
        ])
        .output()
        .unwrap();
    assert!(
        inventory.status.success(),
        "{}",
        String::from_utf8_lossy(&inventory.stderr)
    );
    let summary: Value = serde_json::from_slice(&inventory.stdout).unwrap();
    assert!(summary["review_count"].as_u64().unwrap() >= 5, "{summary}");
    std::fs::remove_dir_all(output).unwrap();
}
