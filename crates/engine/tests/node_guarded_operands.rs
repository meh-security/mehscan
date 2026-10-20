use mehscan_core::{Capability, SecurityPathState};
use std::fs;

#[test]
fn guarded_aliases_and_imported_path_operations_keep_only_proved_operands() {
    let root = std::env::temp_dir().join(format!("mehscan-guarded-aliases-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "typed",
            "const file=params.file; if(!file.includes('/')) res.sendFile(paths.resolve('keys',file));",
            true,
        ),
        (
            "join",
            "const file=params.file; const full=join('logs',file); if(enabled) res.sendFile(full);",
            true,
        ),
        (
            "normalize",
            "const file=params.file; if(enabled) res.sendFile(paths.normalize(file));",
            true,
        ),
        (
            "directAlias",
            "const file=params.file; if(enabled) res.sendFile(file);",
            true,
        ),
        (
            "copy",
            "let file=params.file; const saved=file; file='safe'; if(enabled) res.sendFile(paths.resolve('keys',saved));",
            true,
        ),
        (
            "overwrite",
            "let file=params.file; file='safe'; if(enabled) res.sendFile(paths.resolve('keys',file));",
            false,
        ),
        (
            "branchWrite",
            "let file=params.file; if(other) file='safe'; if(enabled) res.sendFile(paths.resolve('keys',file));",
            false,
        ),
        (
            "update",
            "let file=params.file; file++; if(enabled) res.sendFile(paths.resolve('keys',file));",
            false,
        ),
        (
            "opaque",
            "const file=clean(params.file); if(enabled) res.sendFile(paths.resolve('keys',file));",
            false,
        ),
        (
            "unrelated",
            "const file=params.file; if(enabled) res.sendFile(other.resolve('keys',file));",
            false,
        ),
        (
            "shadow",
            "const file=params.file; if(enabled) { let file; res.sendFile(paths.resolve('keys',file)); }",
            false,
        ),
        (
            "sourceWrite",
            "params.file='safe'; const file=params.file; if(enabled) res.sendFile(paths.resolve('keys',file));",
            false,
        ),
        (
            "methodWrite",
            "const file=params.file; paths.resolve=clean; if(enabled) res.sendFile(paths.resolve('keys',file));",
            false,
        ),
        (
            "methodShadow",
            "const paths=other; const file=params.file; if(enabled) res.sendFile(paths.resolve('keys',file));",
            false,
        ),
        (
            "predicate",
            "const file=params.file; if(file) res.sendFile('/safe');",
            false,
        ),
        (
            "confinement",
            "const file=params.file; const full=paths.resolve('keys',file); if(full.startsWith(rootPrefix)) res.sendFile(full);",
            true,
        ),
        (
            "discarded",
            "const file=params.file; if(enabled) res.sendFile(paths.resolve(file,'/safe/file'));",
            false,
        ),
        (
            "destructuringWrite",
            "let file=params.file; ({file}=clean); if(enabled) res.sendFile(paths.resolve('keys',file));",
            false,
        ),
    ];
    for (index, (name, body, _)) in cases.iter().enumerate() {
        let extension = ["ts", "tsx", "js"][index % 3];
        let handler = if extension == "js" {
            format!(
                "import fs from 'node:fs'; export function handle(req,res) {{ {} }}",
                body.replace("params.file", "req.params.file")
                    .replace("res.sendFile", "fs.readFile")
            )
        } else {
            format!(
                "import {{type Request,type Response}} from 'express'; export function factory() {{ return ({{params}}:Request,res:Response) => {{ {body} }} }}"
            )
        };
        fs::write(
            root.join(format!("{name}.{extension}")),
            format!("import paths, {{ join }} from 'node:path'; {handler}"),
        )
        .unwrap();
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    for (index, (name, _, expected)) in cases.iter().enumerate() {
        let file = format!("{name}.{}", ["ts", "tsx", "js"][index % 3]);
        let paths = scan
            .security_paths
            .iter()
            .filter(|p| {
                p.capability == Capability::FilesystemRead
                    && p.steps.last().is_some_and(|s| s.location.path == file)
            })
            .collect::<Vec<_>>();
        assert_eq!(!paths.is_empty(), *expected, "unexpected flow for {file}");
        for path in paths {
            assert_eq!(path.state, SecurityPathState::Unknown);
            assert!(
                path.uncertainty_reasons
                    .iter()
                    .any(|r| r == "node_guarded_alias_operand_flow")
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn conditional_direct_operands_preserve_values_without_assuming_calls_or_predicates() {
    let root =
        std::env::temp_dir().join(format!("mehscan-guarded-operands-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "uploadCleanup",
            "if (req.file) fs.unlink(req.file.path, callback);",
            false,
            Capability::FilesystemWrite,
        ),
        (
            "bracketOverwrite",
            "req.query['next']='/safe'; if (enabled) res.redirect(req.query.next);",
            false,
            Capability::Redirect,
        ),
        (
            "dynamicOverwrite",
            "req.query[key]='/safe'; if (enabled) res.redirect(req.query.next);",
            false,
            Capability::Redirect,
        ),
        (
            "host",
            "if (req.method === 'GET') res.redirect('https://' + req.headers.host + req.url);",
            true,
            Capability::Redirect,
        ),
        (
            "template",
            "if (req.method === 'GET') res.redirect(`/go/${req.query.next}`);",
            true,
            Capability::Redirect,
        ),
        (
            "file",
            "if (req.method === 'GET') fs.readFile(req.query.path, callback);",
            true,
            Capability::FilesystemRead,
        ),
        (
            "outbound",
            "if (enabled) fetch(req.query.url);",
            true,
            Capability::OutboundNetworkRequest,
        ),
        (
            "templateSource",
            "if (enabled) views.renderString(req.body.template);",
            true,
            Capability::TemplateEvaluation,
        ),
        (
            "predicate",
            "if (req.query.next) res.redirect('/safe');",
            false,
            Capability::Redirect,
        ),
        (
            "choice",
            "if (enabled) res.redirect(req.query.next ? '/one' : '/two');",
            false,
            Capability::Redirect,
        ),
        (
            "call",
            "if (enabled) res.redirect(clean(req.query.next));",
            false,
            Capability::Redirect,
        ),
        (
            "dead",
            "if (false) res.redirect(req.query.next);",
            false,
            Capability::Redirect,
        ),
        (
            "overwrite",
            "req.query.next='/safe'; if (enabled) res.redirect(req.query.next);",
            false,
            Capability::Redirect,
        ),
        (
            "parentOverwrite",
            "req.query={next:'/safe'}; if (enabled) res.redirect(req.query.next);",
            false,
            Capability::Redirect,
        ),
        (
            "unrelated",
            "other.next='/safe'; if (enabled) res.redirect(req.query.next);",
            true,
            Capability::Redirect,
        ),
    ];
    for (index, (name, body, _, _)) in cases.iter().enumerate() {
        let extension = ["js", "ts", "tsx"][index % 3];
        fs::write(root.join(format!("{name}.{extension}")), format!("const fs=require('node:fs'); const views=require('nunjucks'); function handle(req,res) {{ {body} }}")).unwrap();
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    for (index, (name, _, expected, capability)) in cases.iter().enumerate() {
        let file = format!("{name}.{}", ["js", "ts", "tsx"][index % 3]);
        let paths = scan
            .security_paths
            .iter()
            .filter(|p| {
                p.capability == *capability
                    && p.steps.last().is_some_and(|s| s.location.path == file)
            })
            .collect::<Vec<_>>();
        assert_eq!(!paths.is_empty(), *expected, "unexpected flow for {file}");
        for path in paths {
            assert_eq!(path.state, SecurityPathState::Unknown);
            assert!(
                path.uncertainty_reasons
                    .iter()
                    .any(|r| r == "node_guarded_direct_operand_flow")
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}
