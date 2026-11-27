use mehscan_core::{Capability, EvidenceKind};
use std::fs;

#[test]
fn imported_koa_contexts_supply_request_values_without_tainting_state_or_responses() {
    let root = std::env::temp_dir().join(format!("mehscan-koa-boundary-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "redirect",
            "import type {Context} from 'koa';",
            "Context",
            "if(enabled) ctx.redirect(ctx.query.next)",
            true,
        ),
        (
            "constantRedirect",
            "import type {Context} from 'koa';",
            "Context",
            "if(ctx.query.next) ctx.redirect('/fixed')",
            false,
        ),
        (
            "methodReplaced",
            "import type {Context} from 'koa';",
            "Context",
            "const url=ctx.query.next; ctx.redirect=other; ctx.redirect(url)",
            false,
        ),
        (
            "receiverReplaced",
            "import type {Context} from 'koa';",
            "Context",
            "const url=ctx.query.next; ctx=other; ctx.redirect(url)",
            false,
        ),
        (
            "body",
            "import type {Context} from 'koa';",
            "Context",
            "fs.readFile(ctx.request.body.path, done)",
            true,
        ),
        (
            "query",
            "import {type Context as WebContext} from 'koa';",
            "WebContext",
            "if(enabled) fs.readFile(ctx.query.path, done)",
            true,
        ),
        (
            "namespace",
            "import type * as Koa from 'koa';",
            "Koa.Context",
            "if(enabled) fs.readFile(ctx.params.file, done)",
            true,
        ),
        (
            "defaultNamespace",
            "import Koa from 'koa';",
            "Koa.ParameterizedContext<State>",
            "if(enabled) fetch(ctx.request.query.url)",
            true,
        ),
        (
            "alias",
            "import type {Context} from 'koa'; type HttpContext = Context;",
            "HttpContext",
            "if(enabled) fs.readFile(ctx.request.body.path, done)",
            true,
        ),
        (
            "bracket",
            "import type {Context} from 'koa';",
            "Context",
            "if(enabled) fs.readFile(ctx['request']['body']['path'], done)",
            true,
        ),
        (
            "header",
            "import type {Context} from 'koa';",
            "Context",
            "if(enabled) fetch(ctx.get('destination'))",
            true,
        ),
        (
            "cookie",
            "import type {Context} from 'koa';",
            "Context",
            "if(enabled) fetch(ctx.cookies.get('destination'))",
            true,
        ),
        (
            "state",
            "import type {Context} from 'koa';",
            "Context",
            "if(enabled) fs.readFile(ctx.state.path, done)",
            false,
        ),
        (
            "response",
            "import type {Context} from 'koa';",
            "Context",
            "if(enabled) fs.readFile(ctx.body, done)",
            false,
        ),
        (
            "secure",
            "import type {Context} from 'koa';",
            "Context",
            "if(enabled) fetch(ctx.request.secure)",
            false,
        ),
        (
            "unrelated",
            "import type {Context} from 'other-package';",
            "Context",
            "if(enabled) fs.readFile(ctx.request.body.path, done)",
            false,
        ),
        (
            "local",
            "interface Context { request: any }",
            "Context",
            "if(enabled) fs.readFile(ctx.request.body.path, done)",
            false,
        ),
        (
            "write",
            "import type {Context} from 'koa';",
            "Context",
            "ctx.request.body.path = '/safe'; if(enabled) fs.readFile('/safe', done)",
            false,
        ),
        (
            "overwrite",
            "import type {Context} from 'koa';",
            "Context",
            "ctx = other; if(enabled) fs.readFile(ctx.request.body.path, done)",
            false,
        ),
        (
            "opaque",
            "import type {Context} from 'koa';",
            "Context",
            "if(enabled) fs.readFile(clean(ctx.request.body.path), done)",
            false,
        ),
        (
            "shadow",
            "import type {Context} from 'koa';",
            "Context",
            "function nested(ctx) { if(enabled) fs.readFile(ctx.request.body.path, done) }",
            false,
        ),
    ];
    for (index, (name, imports, annotation, body, _)) in cases.iter().enumerate() {
        let extension = if index % 2 == 0 { "ts" } else { "tsx" };
        fs::write(root.join(format!("{name}.{extension}")), format!("import fs from 'node:fs'; {imports} export default {{ async handle(ctx:{annotation}) {{ {body} }} }}")).unwrap();
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    for (index, (name, _, _, _, expected)) in cases.iter().enumerate() {
        let file = format!("{name}.{}", if index % 2 == 0 { "ts" } else { "tsx" });
        let paths = scan
            .security_paths
            .iter()
            .filter(|p| p.steps.last().is_some_and(|s| s.location.path == file))
            .collect::<Vec<_>>();
        assert_eq!(!paths.is_empty(), *expected, "unexpected flow for {file}");
        for path in paths {
            let source = scan
                .evidence
                .iter()
                .find(|e| e.id == path.source_evidence_id)
                .unwrap();
            assert_eq!(source.capability, Capability::HttpRequestData);
            assert!(source.tags.iter().any(|t| t == "koa"));
            assert!(!source.tags.iter().any(|t| t == "express"));
        }
        if [
            "state",
            "response",
            "secure",
            "unrelated",
            "local",
            "write",
            "shadow",
        ]
        .contains(name)
        {
            assert!(
                !scan
                    .evidence
                    .iter()
                    .any(|e| e.location.path == file && e.kind == EvidenceKind::Source),
                "unexpected source for {file}"
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}
