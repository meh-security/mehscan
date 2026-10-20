use mehscan_core::{Capability, SecurityPathState};
use std::fs;

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
