use serde_json::Value;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mehscan-export-navigation-{}-{name}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn put(&self, path: &str, text: &str) {
        let target = self.0.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, text).unwrap();
    }
    fn query(&self, path: &str, name: &str) -> Value {
        serde_json::to_value(
            mehscan_engine::investigation::get_export_target(&self.0, path, name).unwrap(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn named_aliases_follow_only_the_selected_export_graph() {
    let f = Fixture::new("aliases");
    f.put(
        "entry.ts",
        "export { pass as guard } from './middle';\nexport { broken } from './unrelated';",
    );
    f.put(
        "middle.ts",
        "import { check as local } from './leaf'; export { local as pass };",
    );
    f.put("leaf.ts", "export function check() { return false; }");
    f.put("unrelated.ts", "export function broken( {");
    let q = f.query("entry.ts", "guard");
    let r = &q["results"];
    assert_eq!(r["status"], "unique_source_candidate");
    assert_eq!(r["candidate"]["path"], "leaf.ts");
    assert_eq!(r["candidate"]["name"], "check");
    assert_eq!(
        r["parsed_files"],
        serde_json::json!(["entry.ts", "leaf.ts", "middle.ts"])
    );
    assert!(r["scope"].as_str().unwrap().contains("unproven"));
    assert!(
        mehscan_engine::investigation::get_export_target(&f.0, "../outside.ts", "guard").is_err()
    );
    assert!(
        mehscan_engine::investigation::get_export_target(&f.0, "entry.ts", "guard.call()").is_err()
    );
}

#[test]
fn stars_preserve_ambiguity_explicit_precedence_and_default_exclusion() {
    let f = Fixture::new("stars");
    f.put(
        "left.ts",
        "export function guard() { return false; } export default function main() {} ",
    );
    f.put("right.ts", "export function guard() { return true; }");
    f.put(
        "entry.ts",
        "export * from './left'; export * from './right';",
    );
    let q = f.query("entry.ts", "guard");
    assert_eq!(q["results"]["status"], "unresolved_or_ambiguous");
    assert!(q["results"]["candidate"].is_null());
    assert!(f.query("entry.ts", "default")["results"]["candidate"].is_null());
    f.put(
        "ambiguous.ts",
        "export * from './left'; export * from './right';",
    );
    f.put(
        "entry.ts",
        "export * from './ambiguous'; export * from './left';",
    );
    let q = f.query("entry.ts", "guard");
    assert_eq!(q["results"]["ambiguous"], true);
    assert!(q["results"]["candidate"].is_null());
    f.put(
        "entry.ts",
        "export * from './right'; export { guard } from './left';",
    );
    assert_eq!(
        f.query("entry.ts", "guard")["results"]["candidate"]["path"],
        "left.ts"
    );
    f.put("middle.ts", "export * from './left';");
    f.put(
        "entry.ts",
        "export * from './left'; export * from './middle';",
    );
    assert_eq!(
        f.query("entry.ts", "guard")["results"]["candidate"]["path"],
        "left.ts"
    );
}

#[test]
fn default_aliases_and_import_conditions_do_not_guess_missing_builds() {
    let f = Fixture::new("conditions");
    f.put(
        "package.json",
        r#"{"private":true,"workspaces":["packages/*"]}"#,
    );
    f.put("packages/lib/package.json",r#"{"name":"@fixture/lib","exports":{".":{"import":"./import.ts","require":"./require.ts"}}}"#);
    f.put(
        "packages/lib/import.ts",
        "export default function imported() { return false; }",
    );
    f.put(
        "packages/lib/require.ts",
        "export default function required() { return true; }",
    );
    f.put(
        "entry.ts",
        "import selected from '@fixture/lib'; export { selected as guard };",
    );
    let q = f.query("entry.ts", "guard");
    assert_eq!(q["results"]["candidate"]["path"], "packages/lib/import.ts");
    f.put(
        "packages/lib/package.json",
        r#"{"name":"@fixture/lib","exports":"./dist/index.js","source":"./import.ts"}"#,
    );
    let q = f.query("entry.ts", "guard");
    assert_eq!(q["results"]["status"], "incomplete");
    assert!(q["results"]["candidate"].is_null());
}

#[test]
fn cycles_missing_branches_parse_errors_and_reassignment_remain_unresolved() {
    let f = Fixture::new("gaps");
    f.put("entry.ts", "export * from './loop';");
    f.put("loop.ts", "export * from './entry';");
    assert_eq!(
        f.query("entry.ts", "guard")["results"]["status"],
        "incomplete"
    );
    f.put("leaf.ts", "export function guard() { return false; }");
    f.put(
        "entry.ts",
        "export * from './leaf'; export * from './absent';",
    );
    let q = f.query("entry.ts", "guard");
    assert_eq!(q["results"]["status"], "incomplete");
    assert!(q["results"]["candidate"].is_null());
    f.put("entry.ts", "export { guard } from './broken';");
    f.put("broken.ts", "export function guard( {");
    let q = f.query("entry.ts", "guard");
    assert_eq!(q["results"]["gaps"][0]["reason"], "parse_failed");
    f.put(
        "entry.ts",
        "let guard = () => false; guard = () => true; export { guard };",
    );
    assert!(f.query("entry.ts", "guard")["results"]["candidate"].is_null());
    f.put(
        "reassigned.ts",
        "let guard = () => false; guard = () => true; export { guard };",
    );
    f.put(
        "entry.ts",
        "export * from './reassigned'; export * from './leaf';",
    );
    assert!(f.query("entry.ts", "guard")["results"]["candidate"].is_null());
}

#[test]
fn scanner_does_not_drop_an_ambiguous_branch_to_infer_a_unique_target() {
    let f = Fixture::new("scanner-ambiguity");
    f.put("left.ts", "import cp from 'node:child_process'; export function run(value: string) { cp.exec(value); }");
    f.put(
        "right.ts",
        "export function run(value: string) { return value; }",
    );
    f.put(
        "ambiguous.ts",
        "export * from './left'; export * from './right';",
    );
    f.put(
        "entry.ts",
        "export * from './ambiguous'; export * from './left';",
    );
    f.put("caller.ts", "import { run } from './entry'; export function handle(req: any) { run(req.query.command); }");
    f.put("control.ts", "import { run } from './left'; export function handle(req: any) { run(req.query.command); }");
    let scan = mehscan_engine::scan_path(&f.0).unwrap();
    let reaches = |file: &str| {
        scan.security_paths.iter().any(|p| {
            p.capability == mehscan_core::Capability::ProcessExecution
                && p.steps.last().is_some_and(|s| s.location.path == file)
        })
    };
    assert!(reaches("control.ts"));
    assert!(!reaches("caller.ts"));
}

#[test]
fn namespace_and_erased_imports_do_not_become_implementation_candidates() {
    let f = Fixture::new("non-values");
    f.put(
        "leaf.ts",
        "export function guard() {} export default function main() {}",
    );
    for statement in [
        "import * as local from './leaf'; export { local as guard };",
        "import type local from './leaf'; export { local as guard };",
        "import type { guard as local } from './leaf'; export { local as guard };",
        "import { type guard as local } from './leaf'; export { local as guard };",
        "export type { guard } from './leaf';",
        "export type * from './leaf';",
    ] {
        f.put("entry.ts", statement);
        let q = f.query("entry.ts", "guard");
        assert!(q["results"]["candidate"].is_null(), "{statement}: {q}");
    }
}

#[test]
fn depth_file_and_byte_limits_never_choose_a_partial_answer() {
    let f = Fixture::new("limits");
    for i in 0..9 {
        f.put(
            &format!("chain{i}.ts"),
            &format!("export {{ guard }} from './chain{}';", i + 1),
        );
    }
    f.put("chain9.ts", "export function guard() {}");
    let q = f.query("chain0.ts", "guard");
    assert_eq!(q["truncated"], true);
    assert!(q["results"]["candidate"].is_null());
    let mut stars = String::new();
    for i in 0..40 {
        f.put(&format!("leaf{i}.ts"), "export const other = 1;");
        stars += &format!("export * from './leaf{i}';\n");
    }
    f.put("wide.ts", &stars);
    let q = f.query("wide.ts", "guard");
    assert_eq!(q["truncated"], true);
    assert!(q["results"]["parsed_files"].as_array().unwrap().len() <= 32);
    f.put(
        "huge.ts",
        &format!("export function guard() {{}}\n//{}", "x".repeat(262144)),
    );
    let q = f.query("huge.ts", "guard");
    assert_eq!(q["truncated"], true);
    assert!(q["results"]["candidate"].is_null());
}
