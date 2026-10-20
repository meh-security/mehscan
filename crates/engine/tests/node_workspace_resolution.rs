use mehscan_core::{Capability, EvidenceKind};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-node-workspaces-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        for (path, source) in files {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn workspace_conditions_aliases_and_barrels_connect_only_real_selected_exports() {
    let fixture = Fixture::new(&[
        (
            "package.json",
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        ),
        (
            "tsconfig.json",
            r#"{"compilerOptions":{"baseUrl":".","paths":{"@helpers/*":["packages/danger/*"]}}}"#,
        ),
        (
            "packages/danger/package.json",
            r#"{"name":"@lab/danger","exports":{".":{"import":"./barrel.ts","require":"./require.cjs"}}}"#,
        ),
        (
            "packages/danger/barrel.ts",
            "export {execute as invoke} from './exec.js'; export {hash as digest} from './digest.js';",
        ),
        (
            "packages/danger/imported.ts",
            "import {execute as local} from './exec.js'; export {local as invoke};",
        ),
        (
            "packages/danger/digest.ts",
            "import crypto from 'node:crypto';\nexport const hash = (data:string) => crypto.createHash('sha256').update(data).digest('hex');",
        ),
        (
            "digest.ts",
            "import {digest} from '@lab/danger'; export function handle(req:any) { return digest(req.query.value); }",
        ),
        (
            "packages/danger/cycle-a.ts",
            "export * from './cycle-b.js';",
        ),
        (
            "packages/danger/cycle-b.ts",
            "export * from './cycle-a.js';",
        ),
        (
            "packages/danger/override.ts",
            "export * from './exec.js'; export function execute(command:string) { return 'constant'; }",
        ),
        (
            "packages/danger/exec.ts",
            "import child_process from 'node:child_process';\nexport function execute(command:string) { child_process.exec(command); }",
        ),
        (
            "packages/danger/default.ts",
            "import child_process from 'node:child_process'; export default function launch(command:string) { child_process.exec(command); }",
        ),
        (
            "default.ts",
            "import shell from '@helpers/default'; export function handle(req:any) { shell(req.query.command); }",
        ),
        (
            "packages/danger/require.cjs",
            "const child_process = require('child_process'); function launch(command) { child_process.exec(command); } module.exports = {invoke:launch};",
        ),
        (
            "packages/danger/private.ts",
            "import child_process from 'node:child_process'; export function invoke(command:string) { child_process.exec(command); }",
        ),
        (
            "packages/clean/package.json",
            r#"{"name":"@lab/clean","exports":"./index.ts"}"#,
        ),
        (
            "packages/clean/index.ts",
            "import child_process from 'node:child_process'; export function invoke(command:string) { child_process.exec('constant'); }",
        ),
        (
            "packages/missing/package.json",
            r#"{"name":"@lab/missing","exports":"./dist/index.js"}"#,
        ),
        (
            "packages/missing/index.ts",
            "import child_process from 'node:child_process'; export function invoke(command:string) { child_process.exec(command); }",
        ),
        (
            "packages/ambiguous/package.json",
            r#"{"name":"@lab/ambiguous","main":"index.ts"}"#,
        ),
        (
            "packages/ambiguous/index.ts",
            "export * from '../danger/exec.js'; export * from './other.js';",
        ),
        (
            "packages/ambiguous/other.ts",
            "export function execute(command:string) { return command; }",
        ),
        (
            "positive.ts",
            "import {invoke as shell} from '@lab/danger'; export function handle(req:any) { shell(req.query.command); }",
        ),
        (
            "namespace.ts",
            "import * as helpers from '@lab/danger'; export function handle(req:any) { helpers.invoke(req.query.command); }",
        ),
        (
            "alias.ts",
            "import {execute} from '@helpers/exec'; export function handle(req:any) { execute(req.query.command); }",
        ),
        (
            "imported.ts",
            "import {invoke} from '@helpers/imported'; export function handle(req:any) { invoke(req.query.command); }",
        ),
        (
            "cycle.ts",
            "import {execute} from '@helpers/cycle-a'; export function handle(req:any) { execute(req.query.command); }",
        ),
        (
            "override.ts",
            "import {execute} from '@helpers/override'; export function handle(req:any) { execute(req.query.command); }",
        ),
        (
            "require.js",
            "const {invoke:shell} = require('@lab/danger'); function handle(req) { shell(req.query.command); }",
        ),
        (
            "negative.ts",
            "import {invoke} from '@lab/clean'; export function handle(req:any) { invoke(req.query.command); }",
        ),
        (
            "private.ts",
            "import {invoke} from '@lab/danger/private'; export function handle(req:any) { invoke(req.query.command); }",
        ),
        (
            "missing.ts",
            "import {invoke} from '@lab/missing'; export function handle(req:any) { invoke(req.query.command); }",
        ),
        (
            "ambiguous.ts",
            "import {execute} from '@lab/ambiguous'; export function handle(req:any) { execute(req.query.command); }",
        ),
        (
            "constant.ts",
            "import {invoke} from '@lab/danger'; export function handle(req:any) { invoke('constant'); }",
        ),
        ("negative/no-alias/tsconfig.json", "{}"),
        (
            "negative/no-alias/collision.ts",
            "import {execute} from 'packages/danger/exec'; export function handle(req:any) { execute(req.query.command); }",
        ),
    ]);
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    for path in [
        "positive.ts",
        "namespace.ts",
        "alias.ts",
        "imported.ts",
        "default.ts",
        "require.js",
    ] {
        assert!(
            scan.security_paths
                .iter()
                .any(|p| p.capability == Capability::ProcessExecution
                    && p.steps.last().is_some_and(|s| s.location.path == path)),
            "missing {path}: {:#?}",
            scan.diagnostics
        );
    }
    for path in [
        "negative.ts",
        "private.ts",
        "missing.ts",
        "ambiguous.ts",
        "constant.ts",
        "cycle.ts",
        "override.ts",
        "negative/no-alias/collision.ts",
    ] {
        assert!(
            !scan
                .security_paths
                .iter()
                .any(|p| p.steps.last().is_some_and(|s| s.location.path == path)),
            "invented flow for {path}"
        );
    }
    let canonical = |path: &str| {
        scan.evidence
            .iter()
            .find(|e| {
                e.kind == EvidenceKind::Sink
                    && e.location.path == path
                    && e.rule_id.contains("parameter-sink-summary")
            })
            .and_then(|e| e.symbol_resolution.as_ref())
            .map(|s| s.canonical.as_str())
    };
    assert_eq!(
        canonical("positive.ts"),
        Some("packages/danger/exec.execute")
    );
    assert_eq!(
        canonical("require.js"),
        Some("packages/danger/require.launch")
    );
    assert!(
        scan.diagnostics
            .iter()
            .any(|d| d.message.contains("@lab/missing"))
    );
    assert!(
        scan.evidence.iter().any(|e| e.location.path == "digest.ts"
            && e.capability == Capability::FixedFormatTransform
            && e.symbol_resolution
                .as_ref()
                .is_some_and(|s| s.canonical == "packages/danger/digest.hash")),
        "symbol summaries must use the same workspace and export identity"
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    let ids = inventory
        .entries
        .iter()
        .filter(|e| e.path == "alias.ts")
        .map(|e| e.review_id.clone())
        .collect();
    let job = mehscan_engine::investigation::build_selected_review_jobs(
        &fixture.0, &inventory, &ids, None,
    )
    .unwrap();
    assert!(job.reviews.iter().flat_map(|review| &review.facts).any(|fact| fact.location.path == "packages/danger/exec.ts" && fact.symbol == "execute"), "reviewer helper context must follow the same TS workspace alias");
}
