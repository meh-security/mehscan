use mehscan_core::Capability;
use std::fs;

#[test]
fn type_only_star_exports_keep_runtime_summaries_without_exporting_types_as_values() {
    let root = std::env::temp_dir().join(format!("mehscan-type-star-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for (file, source) in [
        (
            "helpers.ts",
            "import cp from 'node:child_process'; export function run(value:string){cp.exec(value);} export function take(value:string){return value;}",
        ),
        ("types.ts", "export interface Options {path:string;}"),
        (
            "barrel.ts",
            "export type * from './types';\nexport {run,take} from './helpers';",
        ),
        (
            "namespace.ts",
            "export type * as Types from './types';\nexport {run} from './helpers';",
        ),
        (
            "local.tsx",
            "export type * from './types';\nimport cp from 'node:child_process'; export function run(value:string){cp.exec(value);}",
        ),
        ("only.ts", "export type * from './helpers';"),
        (
            "invalid.ts",
            "export type * from './types';\nexport {run} from './helpers'; const broken = ;",
        ),
        (
            "malformed.ts",
            "export type * from (missing);\nexport {run} from './helpers';",
        ),
        (
            "invalid.js",
            "export type * from './types'; export {run} from './helpers';",
        ),
        (
            "positive.ts",
            "import {run,take} from './barrel'; import cp from 'node:child_process'; export function handle(req:any){run(req.query.command);cp.exec(take(req.query.command));}",
        ),
        (
            "namespace-positive.ts",
            "import {run} from './namespace'; export function handle(req:any){run(req.query.command);}",
        ),
        (
            "local-positive.ts",
            "import {run} from './local'; export function handle(req:any){run(req.query.command);}",
        ),
        (
            "only-negative.ts",
            "import {run} from './only'; export function handle(req:any){run(req.query.command);}",
        ),
        (
            "invalid-negative.ts",
            "import {run} from './invalid'; export function handle(req:any){run(req.query.command);}",
        ),
        (
            "malformed-negative.ts",
            "import {run} from './malformed'; export function handle(req:any){run(req.query.command);}",
        ),
        (
            "js-negative.ts",
            "import {run} from './invalid.js'; export function handle(req:any){run(req.query.command);}",
        ),
    ] {
        fs::write(root.join(file), source).unwrap();
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    for file in ["positive.ts", "namespace-positive.ts", "local-positive.ts"] {
        assert!(
            scan.security_paths
                .iter()
                .any(|p| p.capability == Capability::ProcessExecution
                    && p.steps.last().unwrap().location.path == file),
            "lost runtime export in {file}"
        );
    }
    assert!(
        scan.security_paths.iter().all(|p| !p
            .steps
            .last()
            .unwrap()
            .location
            .path
            .contains("negative")),
        "invented runtime export"
    );
    let failures = scan
        .diagnostics
        .iter()
        .filter_map(|d| d.path.as_deref())
        .collect::<Vec<_>>();
    for file in ["barrel.ts", "namespace.ts", "local.tsx", "only.ts"] {
        assert!(
            !failures.contains(&file),
            "erased export marked invalid in {file}"
        );
    }
    for file in ["invalid.ts", "malformed.ts", "invalid.js"] {
        assert!(
            failures.contains(&file),
            "unrelated syntax error hidden in {file}"
        );
    }
    fs::remove_dir_all(root).unwrap();
}
