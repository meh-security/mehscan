use std::{
    collections::BTreeSet,
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn generated_frontend_assets_are_outside_both_queues_while_authored_neighbors_remain() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-frontend-scope-cli-{}-{nonce}",
        std::process::id()
    ));
    let artifacts = root.with_extension("inventory");
    let excluded = [
        "app/.output",
        "app/.angular",
        "app/_next/static",
        "docs/.vitepress/cache",
        ".yarn/unplugged",
    ];
    let authored = [
        "app/server",
        "docs/.vitepress/theme",
        "docs/.vuepress/components",
        ".yarn/plugins",
    ];
    for directory in excluded.iter().chain(authored.iter()) {
        fs::create_dir_all(root.join(directory)).unwrap();
        fs::write(
            root.join(directory).join("code.js"),
            "export function interpret(req) { return eval(req.body.code); }\n",
        )
        .unwrap();
    }
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
    let expected: BTreeSet<_> = authored
        .iter()
        .map(|dir| format!("{dir}/code.js"))
        .collect();
    for selection in ["value", "all"] {
        let list = run(&[
            "investigate",
            "review-inventory-list",
            "--inventory",
            artifacts.to_str().unwrap(),
            "--selection",
            selection,
            "--limit",
            "100",
        ]);
        let paths: BTreeSet<_> = list["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            paths, expected,
            "{selection}: lost authored work or admitted generated assets"
        );
    }
    let provenance = run(&[
        "investigate",
        "provenance",
        root.to_str().unwrap(),
        "--inventory",
        artifacts.to_str().unwrap(),
    ]);
    let ignored = provenance["excluded_subtrees"].as_array().unwrap();
    for directory in excluded {
        assert!(
            ignored.iter().any(|path| path == &format!("{directory}/")),
            "missing excluded boundary {directory}"
        );
    }
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(artifacts).unwrap();
}
