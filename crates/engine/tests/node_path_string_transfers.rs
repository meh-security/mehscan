use mehscan_core::{Capability, SecurityPathState};
use std::fs;

#[test]
fn partial_replacements_keep_only_proven_path_string_receivers() {
    let root = std::env::temp_dir().join(format!("mehscan-path-strings-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "prefix",
            r"const p=paths.normalize(req.query.file).replace(/^[\\/]+/, '');",
            true,
        ),
        (
            "suffix",
            r"const p=paths.normalize(req.query.file).replace(/[. ]+$/, '');",
            true,
        ),
        (
            "literal",
            "const p=paths.join('base',req.query.file).replace('..','.');",
            true,
        ),
        (
            "renamed",
            r"const p=normalize(req.query.file).replace(/^[ ]+/, '');",
            true,
        ),
        (
            "copy",
            r"const normalized=paths.normalize(req.query.file); const p=normalized.replace(/^[\\/]+/, '');",
            true,
        ),
        (
            "bracket",
            r"const p=paths.normalize(req.query['file']).replace(/^[\\/]+/g, '');",
            true,
        ),
        (
            "whitespace",
            r"const p=paths.normalize(req.query.file).replace(/^[\s]+/, '');",
            true,
        ),
        (
            "callback",
            r"const p=paths.normalize(req.query.file).replace(/^[\\/]+/, ()=>'/safe');",
            false,
        ),
        (
            "fullValue",
            "const p=paths.normalize(req.query.file).replace(/^.*$/, '/safe');",
            false,
        ),
        (
            "allCharacters",
            r"const p=paths.normalize(req.query.file).replace(/^[\s\S]+/, '/safe');",
            false,
        ),
        (
            "bothEdges",
            r"const p=paths.normalize(req.query.file).replace(/^[\\/]+$/, '/safe');",
            false,
        ),
        (
            "unknownRegex",
            "const p=paths.normalize(req.query.file).replace(pattern, '');",
            false,
        ),
        (
            "unrelated",
            r"const p=other.normalize(req.query.file).replace(/^[\\/]+/, '');",
            false,
        ),
        (
            "unknownReceiver",
            r"const p=req.query.file.replace(/^[\\/]+/, '');",
            false,
        ),
        (
            "constant",
            r"const p=paths.normalize('/safe').replace(/^[\\/]+/, ''); touch(req.query.file);",
            false,
        ),
        (
            "searchOnly",
            "const p=paths.normalize('/safe').replace(req.query.file, '');",
            false,
        ),
        (
            "replacementOnly",
            "const p=paths.normalize('/safe').replace('safe', req.query.file);",
            false,
        ),
        (
            "overwrite",
            r"let normalized=paths.normalize(req.query.file); normalized='/safe'; const p=normalized.replace(/^[\\/]+/, '');",
            false,
        ),
        (
            "branchWrite",
            r"let normalized=paths.normalize(req.query.file); if(other) normalized='/safe'; const p=normalized.replace(/^[\\/]+/, '');",
            false,
        ),
        (
            "shadow",
            r"const paths=other; const p=paths.normalize(req.query.file).replace(/^[\\/]+/, '');",
            false,
        ),
        (
            "methodWrite",
            r"paths.normalize=other; const p=paths.normalize(req.query.file).replace(/^[\\/]+/, '');",
            false,
        ),
        (
            "prototypeWrite",
            r"String.prototype.replace=other; const p=paths.normalize(req.query.file).replace(/^[\\/]+/, '');",
            false,
        ),
        (
            "regexWrite",
            r"RegExp.prototype[Symbol.replace]=other; const p=paths.normalize(req.query.file).replace(/^[\\/]+/, '');",
            false,
        ),
        (
            "discarded",
            r"const p=paths.resolve(paths.normalize(req.query.file).replace(/^[\\/]+/, ''), '/safe');",
            false,
        ),
    ];
    for (name, body, _) in cases {
        for ext in ["js", "ts", "tsx"] {
            let types = if ext == "js" { "" } else { ":any" };
            fs::write(root.join(format!("{name}.{ext}")), format!(
                "import paths, {{normalize}} from 'node:path'; import fs from 'node:fs'; export function handle(req{types}){{{body} if(enabled) fs.readFile(p);}}"
            )).unwrap();
        }
    }
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for (name, _, expected) in cases {
        for ext in ["js", "ts", "tsx"] {
            let file = format!("{name}.{ext}");
            let paths = result
                .security_paths
                .iter()
                .filter(|p| {
                    p.capability == Capability::FilesystemRead
                        && p.steps.last().is_some_and(|s| s.location.path == file)
                })
                .collect::<Vec<_>>();
            assert_eq!(
                !paths.is_empty(),
                expected,
                "wrong receiver contribution: {file}"
            );
            for path in paths {
                assert_eq!(path.state, SecurityPathState::Unknown);
                assert!(
                    path.uncertainty_reasons
                        .iter()
                        .any(|r| r == "control_flow_context_not_modeled")
                );
                assert!(path.steps.iter().any(|s| {
                    s.symbol
                        .as_ref()
                        .is_some_and(|s| s.starts_with("String.replace:"))
                }));
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn url_scalar_origins_require_the_express_type_boundary() {
    let root = std::env::temp_dir().join(format!("mehscan-express-url-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "path",
            "import type {Request} from 'express';",
            "req:Request",
            "req.path",
            true,
        ),
        (
            "url",
            "import type {Request as Incoming} from 'express-serve-static-core';",
            "incoming:Incoming",
            "incoming.url",
            true,
        ),
        (
            "original",
            "import type * as E from 'express';",
            "request:E.Request",
            "request.originalUrl",
            true,
        ),
        (
            "bracket",
            "import type {Request} from 'express';",
            "req:Request",
            "req['path']",
            true,
        ),
        (
            "lookalike",
            "type Request={path:string};",
            "req:Request",
            "req.path",
            false,
        ),
        (
            "unrelated",
            "import type {Request} from 'other-framework';",
            "req:Request",
            "req.path",
            false,
        ),
        (
            "unknown",
            "import type {Request} from 'express';",
            "req:any",
            "req.path",
            false,
        ),
        (
            "nested",
            "import type {Request} from 'express';",
            "req:Request",
            "req.path.something",
            false,
        ),
        (
            "local",
            "import type {Request} from 'express';",
            "req:Request",
            "({path:'/safe'}).path",
            false,
        ),
    ];
    for (name, import, parameter, source, _) in cases {
        fs::write(root.join(format!("{name}.ts")), format!(
            "{import} import path from 'node:path'; import fs from 'node:fs'; export function handle({parameter}){{const filePath=path.resolve('root',path.normalize({source}).replace(/^[\\\\/]+/,'')); if(!filePath.startsWith(path.resolve('root'))){{return;}} if(enabled) fs.readFile(filePath);}}"
        )).unwrap();
    }
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for (name, _, _, source, expected) in cases {
        let file = format!("{name}.ts");
        let paths = result
            .security_paths
            .iter()
            .filter(|p| {
                p.capability == Capability::FilesystemRead
                    && p.steps.last().is_some_and(|s| s.location.path == file)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            !paths.is_empty(),
            expected,
            "wrong URL scalar origin: {file}"
        );
        if expected {
            let origin = result
                .evidence
                .iter()
                .find(|e| e.id == paths[0].source_evidence_id)
                .unwrap();
            assert!(
                origin
                    .provenance
                    .engine
                    .ends_with("bounded-express-type-boundary")
            );
            assert_eq!(
                origin.captures["request"].text,
                source.split(['.', '[']).next().unwrap()
            );
            assert_eq!(paths[0].state, SecurityPathState::Unknown);
        }
    }
    fs::remove_dir_all(root).unwrap();
}
