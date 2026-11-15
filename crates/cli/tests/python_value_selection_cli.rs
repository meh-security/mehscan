use serde_json::Value;
use std::{fs, process::Command};

fn run(args: &[&str]) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(args)
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
fn python_value_plans_retain_the_complete_chain_and_comprehensive_ids() {
    let base =
        std::env::temp_dir().join(format!("mehscan-python-value-cli-{}", std::process::id()));
    let root = base.join("source");
    fs::create_dir_all(&root).unwrap();
    let chain = "Row.objects.filter(pk__in=keys).filter(kind=kind).delete()";
    fs::write(root.join("app.py"), format!("from django.http import HttpResponse\ndef view(keys, kind):\n    {chain}\n    return HttpResponse(status=200)\n")).unwrap();
    let inventory = base.join("inventory");
    run(&[
        "investigate",
        "review-inventory",
        root.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
        "--repository-key",
        "fixture:python-value",
    ]);
    let inv: Value =
        serde_json::from_slice(&fs::read(inventory.join("inventory.json")).unwrap()).unwrap();
    let rows = inv["entries"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let plan = |policy| {
        run(&[
            "state",
            "plan-template",
            "--inventory",
            inventory.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
            "--policy",
            policy,
            "--selection",
            "policy",
        ])
    };
    let value = plan("value");
    assert_eq!(value["selected_review_ids"].as_array().unwrap().len(), 1);
    assert_eq!(value["deferred_review_ids"].as_object().unwrap().len(), 2);
    let representative = value["selected_review_ids"][0].as_str().unwrap();
    let child = rows
        .iter()
        .find(|r| r["value_hint"]["reason"] == "python_shared_orm_receiver_chain")
        .unwrap();
    assert_eq!(child["value_hint"]["depends_on"], representative);
    assert!(
        value["deferred_review_ids"][child["review_id"].as_str().unwrap()]
            .as_str()
            .unwrap()
            .contains(representative)
    );
    let comprehensive = plan("comprehensive");
    assert_eq!(
        comprehensive["selected_review_ids"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(
        comprehensive["deferred_review_ids"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    let bundles = base.join("bundles");
    run(&[
        "investigate",
        "review-bundles",
        root.to_str().unwrap(),
        "--inventory",
        inventory.to_str().unwrap(),
        "--review-ids",
        representative,
        "--output",
        bundles.to_str().unwrap(),
    ]);
    let manifest: Value =
        serde_json::from_slice(&fs::read(bundles.join("manifest.json")).unwrap()).unwrap();
    let request = bundles
        .join("requests")
        .join(manifest["bundles"][0]["filename"].as_str().unwrap());
    let card = run(&[
        "investigate",
        "review-card",
        "--bundle",
        request.to_str().unwrap(),
        "--review-id",
        representative,
    ]);
    let context = card["helper_context"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["role"] == "python_orm_shared_chain_context")
        .unwrap();
    assert_eq!(context["excerpt"], chain);
    assert_eq!(context["verified"], false);
    fs::remove_dir_all(base).unwrap();
}
