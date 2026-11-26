use mehscan_core::Capability;
use std::fs;

#[test]
fn navigation_contribution_is_ordered_and_shared_across_frameworks() {
    let root =
        std::env::temp_dir().join(format!("mehscan-url-contribution-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "queryAlias",
            "const target='/search?q='+req.query.next; if(enabled) res.redirect(target);",
            true,
            Some(false),
        ),
        (
            "nestedMutation",
            "let target='/go/'+req.query.next; function mutate(){target=other;} mutate(); if(enabled) res.redirect(target);",
            false,
            None,
        ),
        (
            "query",
            "if(enabled) res.redirect('/search?q='+req.query.next);",
            true,
            Some(false),
        ),
        (
            "httpPath",
            "if(enabled) res.redirect(`https://example.test/a/${req.query.next}`);",
            true,
            Some(false),
        ),
        (
            "relative",
            "if(enabled) res.redirect('/go/'+req.query.next);",
            true,
            Some(false),
        ),
        (
            "fragment",
            "if(enabled) res.redirect('/home#'+req.query.next);",
            true,
            Some(false),
        ),
        (
            "authority",
            "if(enabled) res.redirect('https://'+req.query.next+'/a');",
            false,
            Some(true),
        ),
        (
            "openAuthority",
            "if(enabled) res.redirect('https://example.test'+req.query.next);",
            false,
            Some(true),
        ),
        (
            "protocolRelative",
            "if(enabled) res.redirect('//'+req.query.next);",
            false,
            Some(true),
        ),
        (
            "slash",
            "if(enabled) res.redirect('/'+req.query.next);",
            false,
            Some(true),
        ),
        (
            "suffix",
            "if(enabled) res.redirect(req.query.next+'/fixed');",
            false,
            Some(true),
        ),
        (
            "unknownBase",
            "if(enabled) res.redirect(base+'/search?q='+req.query.next);",
            false,
            Some(true),
        ),
        (
            "opaqueScheme",
            "if(enabled) res.redirect('javascript:run('+req.query.next+')');",
            false,
            Some(true),
        ),
        (
            "opaque",
            "if(enabled) res.redirect(clean('/search?q='+req.query.next));",
            false,
            None,
        ),
        (
            "opaqueSuffix",
            "if(enabled) res.redirect('/go/'+clean(req.query.next));",
            true,
            Some(false),
        ),
        (
            "urlObject",
            "const url=new URL(req.query.next,base); if(enabled) res.redirect(url.toString());",
            false,
            Some(true),
        ),
        (
            "predicate",
            "if(enabled) res.redirect(req.query.next?'/one':'/two');",
            true,
            Some(false),
        ),
        (
            "predicateAlias",
            "const flag=req.query.next; if(enabled) res.redirect(flag?'/one':'/two');",
            true,
            Some(false),
        ),
        (
            "selectedValue",
            "if(enabled) res.redirect(flag?req.query.next:'/one');",
            false,
            None,
        ),
        (
            "overwritten",
            "let target='/go/'+req.query.next; target=other; if(enabled) res.redirect(target);",
            false,
            None,
        ),
        (
            "branchWrite",
            "let prefix='/go/'; if(other) prefix=other; if(enabled) res.redirect(prefix+req.query.next);",
            false,
            Some(true),
        ),
        (
            "unknownSuffix",
            "if(enabled) res.redirect(unknownUrl+'/fixed');",
            false,
            Some(false),
        ),
    ];
    for (name, body, _, _) in cases {
        fs::write(
            root.join(format!("express-{name}.js")),
            format!("export function handle(req,res) {{ {body} }}"),
        )
        .unwrap();
        fs::write(
            root.join(format!("koa-{name}.ts")),
            format!(
                "import type {{Context}} from 'koa'; export function handle(ctx:Context) {{ {} }}",
                body.replace("req.query", "ctx.query")
                    .replace("res.redirect", "ctx.redirect")
            ),
        )
        .unwrap();
    }
    fs::write(root.join("http-known-host.js"),"export function handle(req) { if(enabled) fetch('http://127.0.0.1/internal/'+req.query.path); }").unwrap();
    fs::write(
        root.join("http-unknown-prefix.js"),
        "export function handle() { if(enabled) fetch(unknownUrl+'https://fixed.example/path'); }",
    )
    .unwrap();
    fs::write(
        root.join("http-known-prefix.js"),
        "if(enabled) fetch('https://fixed.example/path?q='+unknownValue);",
    )
    .unwrap();
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    for (name, _, closed, paths) in cases {
        for (framework, extension) in [("express", "js"), ("koa", "ts")] {
            let file = format!("{framework}-{name}.{extension}");
            let sink = inventory
                .scan
                .evidence
                .iter()
                .find(|e| e.location.path == file && e.capability == Capability::Redirect)
                .unwrap();
            assert_eq!(
                sink.tags.iter().any(|t| t.starts_with("redirect-closure:")),
                closed,
                "unexpected closure for {file}"
            );
            let actual = inventory
                .scan
                .security_paths
                .iter()
                .any(|p| p.sink_evidence_id == sink.id);
            if let Some(expected) = paths {
                assert_eq!(actual, expected, "unexpected path for {file}");
            }
            if closed {
                assert!(
                    !inventory
                        .entries
                        .iter()
                        .any(|e| e.path == file && e.capability == Capability::Redirect),
                    "closed target still admitted for {file}"
                );
            }
            if name == "unknownBase" {
                assert!(
                    inventory
                        .scan
                        .security_paths
                        .iter()
                        .filter(|p| p.sink_evidence_id == sink.id)
                        .all(|p| p
                            .uncertainty_reasons
                            .iter()
                            .any(|r| r == "node_url_query_suffix_base_unclassified"))
                );
            }
            if name == "unknownSuffix" && framework == "express" {
                assert!(
                    inventory
                        .entries
                        .iter()
                        .any(|e| e.path == file && e.capability == Capability::Redirect),
                    "suffix literal must not suppress an unknown destination"
                );
            }
        }
    }
    for (file, fixed_authority, admitted) in [
        ("http-known-host.js", true, true),
        ("http-unknown-prefix.js", false, true),
        ("http-known-prefix.js", true, false),
    ] {
        let sink = inventory
            .scan
            .evidence
            .iter()
            .find(|e| e.location.path == file && e.capability == Capability::OutboundNetworkRequest)
            .unwrap();
        assert_eq!(
            sink.tags
                .iter()
                .any(|tag| tag == "url-shape:fixed-http-authority"),
            fixed_authority,
            "wrong HTTP authority fact for {file}"
        );
        assert_eq!(
            inventory
                .entries
                .iter()
                .any(|e| e.path == file && e.capability == Capability::OutboundNetworkRequest),
            admitted,
            "wrong HTTP admission for {file}"
        );
    }
    fs::remove_dir_all(root).unwrap();
}
