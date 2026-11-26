use mehscan_core::Capability;
use std::fs;

#[test]
fn unresolved_imports_do_not_prove_return_flow_but_keep_sink_and_transfer_proofs() {
    let root = std::env::temp_dir().join(format!("mehscan-opaque-returns-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for (name, source) in [
        (
            "helpers.ts",
            "export function pass(value){return value;} export function clean(value){return 'safe';} export function field(value){return {command:value};}",
        ),
        ("barrel.ts", "export type * from './helpers';"),
    ] {
        fs::write(root.join(name), source).unwrap();
    }
    let cases = [
        (
            "missingFile",
            "import {take as renamed} from './missing';",
            "cp.exec(renamed(req.query.command));",
            false,
        ),
        (
            "missingExport",
            "import {take as renamed} from './helpers';",
            "cp.exec(renamed(req.query.command));",
            false,
        ),
        (
            "erasedExport",
            "import {pass} from './barrel';",
            "cp.exec(pass(req.query.command));",
            false,
        ),
        (
            "namespaceMissingFile",
            "import * as helpers from './missing';",
            "cp.exec(helpers.take(req.query.command));",
            false,
        ),
        (
            "namespaceMissingMember",
            "import * as helpers from './helpers';",
            "cp.exec(helpers.take(req.query.command));",
            false,
        ),
        (
            "namespaceErasedExport",
            "import * as helpers from './barrel';",
            "cp.exec(helpers.pass(req.query.command));",
            false,
        ),
        (
            "requireMissingFile",
            "const {take:renamed}=require('./missing');",
            "cp.exec(renamed(req.query.command));",
            false,
        ),
        (
            "requireMissingMember",
            "const helpers=require('./helpers');",
            "cp.exec(helpers.take(req.query.command));",
            false,
        ),
        (
            "assignedOpaque",
            "import {take} from './missing';",
            "const value=take(req.query.command); cp.exec(value);",
            false,
        ),
        (
            "assignedTransfer",
            "import {pass} from './helpers';",
            "const value=pass(req.query.command); cp.exec(value);",
            true,
        ),
        (
            "assignedDirect",
            "import {take} from './missing';",
            "const value=req.query.command; take('safe'); cp.exec(value);",
            true,
        ),
        (
            "cleanReturn",
            "import {clean} from './helpers';",
            "cp.exec(clean(req.query.command));",
            false,
        ),
        (
            "renamedTransfer",
            "import {pass as renamed} from './helpers';",
            "cp.exec(renamed(req.query.command));",
            true,
        ),
        (
            "namespaceTransfer",
            "import * as helpers from './helpers';",
            "cp.exec(helpers.pass(req.query.command));",
            true,
        ),
        (
            "fieldTransfer",
            "import {field} from './helpers';",
            "const dto=field(req.query.command); cp.exec(dto.command);",
            true,
        ),
        (
            "directSink",
            "import {take} from './missing';",
            "take(cp.exec(req.query.command));",
            true,
        ),
        (
            "directOperand",
            "import {take} from './missing';",
            "cp.exec(take(req.query.other)+req.query.command);",
            true,
        ),
    ];
    for (name, imports, body, _) in cases {
        for ext in ["js", "ts", "tsx"] {
            fs::write(root.join(format!("{name}.{ext}")), format!("import cp from 'node:child_process'; {imports} export function handle(req){{ {body} }}")).unwrap();
        }
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for (name, _, _, expected) in cases {
        for ext in ["js", "ts", "tsx"] {
            let file = format!("{name}.{ext}");
            let sink = scan
                .evidence
                .iter()
                .find(|e| e.location.path == file && e.capability == Capability::ProcessExecution)
                .unwrap();
            let paths = scan
                .security_paths
                .iter()
                .filter(|p| p.sink_evidence_id == sink.id)
                .collect::<Vec<_>>();
            assert_eq!(!paths.is_empty(), expected, "wrong return proof for {file}");
            if name == "directOperand" {
                let source_text = fs::read_to_string(root.join(&file)).unwrap();
                assert!(
                    paths.iter().all(|p| {
                        let source = scan
                            .evidence
                            .iter()
                            .find(|e| e.id == p.source_evidence_id)
                            .unwrap();
                        let start = source.location.start.byte_offset as usize;
                        let end = source.location.end.byte_offset as usize;
                        source_text[start..end].contains("command")
                    }),
                    "opaque argument must not be proved by the sibling direct operand: {file}"
                );
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}
