use mehscan_core::{Capability, EvidenceKind};
use std::fs;

#[test]
fn typed_whole_request_reads_are_sources_but_writes_and_schema_returns_are_not() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-request-collections-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "direct",
            "Request",
            "return Record.findByPk(req.query)",
            true,
            true,
        ),
        (
            "alias",
            "Request",
            "const key=req.query; return Record.findByPk(key)",
            true,
            true,
        ),
        (
            "body",
            "Request",
            "return Record.findByPk(req.body)",
            true,
            true,
        ),
        (
            "contextual",
            "handler",
            "return Record.findByPk(req.params)",
            true,
            true,
        ),
        (
            "overwritten",
            "Request",
            "req.body='fixed'; return Record.findByPk(req.body)",
            false,
            false,
        ),
        (
            "receiver",
            "Request",
            "req=other; return Record.findByPk(req.body)",
            false,
            false,
        ),
        (
            "fieldWrite",
            "Request",
            "req.body.id='fixed'; return Record.findByPk(req.body)",
            false,
            false,
        ),
        (
            "deleted",
            "Request",
            "delete req.body; return Record.findByPk(req.body)",
            false,
            false,
        ),
        (
            "unrelated",
            "OtherRequest",
            "return Record.findByPk(req.body)",
            false,
            false,
        ),
        (
            "nested",
            "Request",
            "function inner(req:OtherRequest){return Record.findByPk(req.body)}",
            false,
            false,
        ),
        (
            "parse",
            "Request",
            "const value=schema.parse(req.body); return Record.findByPk(value.id)",
            true,
            false,
        ),
        (
            "safeParse",
            "Request",
            "const value=schema.safeParse(req.body); return Record.findByPk(value.data.id)",
            true,
            false,
        ),
        (
            "cleanTransform",
            "Request",
            "const value=z.object({id:z.string().transform(()=> 'fixed')}).parse(req.body); return Record.findByPk(value.id)",
            true,
            false,
        ),
    ];
    for (name, ty, body, _, _) in cases {
        for extension in ["ts", "tsx"] {
            let handler = if ty == "handler" {
                format!("export const handle:RequestHandler=(req,res)=>{{{body}}}")
            } else {
                format!("export function handle(req:{ty}){{{body}}}")
            };
            fs::write(root.join(format!("{name}.{extension}")), format!("import type {{Request,RequestHandler}} from 'express'; import {{Record}} from './models'; import {{z}} from 'zod'; {handler}")).unwrap();
        }
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for (name, _, _, source_expected, path_expected) in cases {
        for extension in ["ts", "tsx"] {
            let path = format!("{name}.{extension}");
            let sources = scan
                .evidence
                .iter()
                .filter(|e| {
                    e.location.path == path
                        && e.kind == EvidenceKind::Source
                        && e.rule_id.ends_with("-express-typed-request-data")
                })
                .collect::<Vec<_>>();
            assert_eq!(!sources.is_empty(), source_expected, "source: {path}");
            assert!(sources.iter().all(|e| {
                e.tags
                    .iter()
                    .any(|t| t == "flow-contract:exact-node-operand")
            }));
            let sink = scan
                .evidence
                .iter()
                .find(|e| e.location.path == path && e.capability == Capability::ResourceAccess)
                .unwrap();
            assert_eq!(
                scan.security_paths
                    .iter()
                    .any(|p| p.sink_evidence_id == sink.id),
                path_expected,
                "path: {path}"
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}
