use mehscan_core::{Capability, EvidenceKind, SecurityPathState};
use std::fs;

#[test]
fn registered_request_metadata_uses_exact_router_and_callback_identity() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-express-registration-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let setup = "const framework=require('express'); const api=framework.Router();";
    let handler = "(incoming,res)=>{if(enabled) res.redirect(`https://${incoming.hostname}${incoming.originalUrl}`)}";
    let cases = [
        ("common", setup.to_string(), format!("api.all('/*',{handler});"), true),
        ("esm", "import framework from 'express'; const api=framework();".into(), format!("api.get('/',{handler});"), true),
        ("namedImport", "import {Router as Make} from 'express'; const api=Make();".into(), format!("api.post('/',{handler});"), true),
        ("requireAlias", "const {Router:Make}=require('express'); const api=Make();".into(), format!("api.use({handler});"), true),
        ("namedHandler", setup.into(), "function handler(incoming,res){if(enabled) res.redirect(`https://${incoming.hostname}${incoming.originalUrl}`)} api.options('/',handler);".into(), true),
        ("chain", setup.into(), format!("api.route('/').head({handler});"), true),
        ("bracket", setup.into(), "api.all('/',(incoming,res)=>{if(enabled) res.redirect(`https://${incoming['hostname']}`)});".into(), true),
        ("error", setup.into(), "api.use((err,incoming,res,next)=>{if(enabled) res.redirect(`https://${incoming.hostname}`)});".into(), true),
        ("unrelated", "const framework=require('other'); const api=framework.Router();".into(), format!("api.all('/',{handler});"), false),
        ("unregistered", setup.into(), "function unused(incoming,res){if(enabled) res.redirect(`https://${incoming.hostname}`)}".into(), false),
        ("methodWrite", setup.into(), format!("api.all=other; api.all('/',{handler});"), false),
        ("dynamicWrite", setup.into(), format!("api[key]=other; api.all('/',{handler});"), false),
        ("factoryWrite", "const framework=require('express'); framework.Router=other; const api=framework.Router();".into(), format!("api.all('/',{handler});"), false),
        ("rebound", "const framework=require('express'); let api=framework.Router(); api=other;".into(), format!("api.all('/',{handler});"), false),
        ("factoryShadow", "const framework=require('express');".into(), format!("function mount(framework){{const api=framework.Router(); api.all('/',{handler});}}"), false),
        ("siblingReceiver", "const framework=require('express'); function unused(){const api=framework.Router();}".into(), format!("function mount(){{const api=other; api.all('/',{handler});}}"), false),
        ("nested", setup.into(), "api.all('/',(incoming,res)=>{function nested(incoming){if(enabled) res.redirect(`https://${incoming.hostname}`)}nested(clean)});".into(), false),
        ("overwrite", setup.into(), "api.all('/',(incoming,res)=>{incoming.hostname='example.org';if(enabled) res.redirect(`https://${incoming.hostname}`)});".into(), false),
        ("requestReplaced", setup.into(), "api.all('/',(incoming,res)=>{incoming=other;if(enabled) res.redirect(`https://${incoming.hostname}`)});".into(), false),
        ("errorArgument", setup.into(), "api.use((err,incoming,res,next)=>{if(enabled) res.redirect(`https://${err.hostname}`)});".into(), false),
        ("blockReceiver", "const framework=require('express'); {const api=framework.Router();}".into(), format!("api.all('/',{handler});"), false),
        ("blockHandler", setup.into(), format!("{{const callback={handler};}} api.all('/',callback);"), false),
        ("deleteField", setup.into(), "api.all('/',(incoming,res)=>{delete incoming.hostname;if(enabled) res.redirect(`https://${incoming.hostname}`)});".into(), false),
        ("singleArrow", setup.into(), "const fs=require('node:fs'); api.get('/',incoming=>{if(enabled)fs.readFile(incoming.path)});".into(), true),
        ("defaultArity", setup.into(), "api.use((err,incoming,res,next=0)=>{if(enabled)res.redirect(`https://${incoming.hostname}`)});".into(), false),
        ("excessArity", setup.into(), "api.use((incoming,res,next,a,b)=>{if(enabled)res.redirect(`https://${incoming.hostname}`)});".into(), false),
    ];
    for (i, (name, setup, body, _)) in cases.iter().enumerate() {
        let ext = ["js", "ts", "tsx"][i % 3];
        fs::write(
            root.join(format!("{name}.{ext}")),
            format!("{setup}\n{body}"),
        )
        .unwrap();
    }
    fs::write(root.join("opaque-result.js"), format!("{setup} api.get('/',(incoming,res)=>{{const parsed=convert(incoming.path);if(enabled)res.redirect(parsed.locale);}});")).unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for (i, (name, _, _, expected)) in cases.iter().enumerate() {
        let file = format!("{name}.{}", ["js", "ts", "tsx"][i % 3]);
        let sources = result
            .evidence
            .iter()
            .filter(|e| {
                e.location.path == file
                    && e.kind == EvidenceKind::Source
                    && e.provenance
                        .engine
                        .ends_with("bounded-express-registration-boundary")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            !sources.is_empty(),
            *expected,
            "wrong registration origin: {file}"
        );
        for source in sources {
            assert!(source.captures["registration"].text.starts_with("api."));
            let paths = result
                .security_paths
                .iter()
                .filter(|p| p.source_evidence_id == source.id)
                .collect::<Vec<_>>();
            assert!(!paths.is_empty(), "no source-supported sink in {file}");
            assert!(paths.iter().all(|p| matches!(
                p.capability,
                Capability::Redirect | Capability::FilesystemRead
            ) && p.state == SecurityPathState::Unknown));
        }
    }
    assert!(result.evidence.iter().any(|e| {
        e.location.path == "opaque-result.js"
            && e.kind == EvidenceKind::Source
            && e.tags
                .iter()
                .any(|t| t == "flow-contract:exact-node-operand")
    }));
    assert!(
        !result.security_paths.iter().any(|p| p
            .steps
            .last()
            .is_some_and(|s| s.location.path == "opaque-result.js")),
        "a request origin must not imply an opaque helper's returned field is tainted"
    );
    fs::remove_dir_all(root).unwrap();
}
