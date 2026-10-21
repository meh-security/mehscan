use mehscan_core::{Capability, EvidenceKind};
use mehscan_engine::investigation::build_review_inventory;
use std::fs;

#[test]
fn imported_got_dispatches_keep_effective_destinations_and_factory_context() {
    let root = std::env::temp_dir().join(format!("mehscan-got-client-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("app.js"),r#"
import request from 'got';
export function direct(req) { return request.post(req.body.target, {json: req.body.data}); }
export function streamed(url) { return request.stream.get(url); }
export function factory(base) { const client=request.extend({prefixUrl:base}); return client.get('path'); }
export function chained(url) { return request.extend({timeout:1000}).post(url); }
export function overridden(req) { return request.get('https://fixed.example', {url:req.query.override}); }
export function hooked(url) { const client=request.extend({hooks:{beforeRequest:[url]}}); return client('https://fixed.example'); }
export function fixed() { return request.get('https://fixed.example', {headers:{accept:'application/json'}}); }
export function fixedPrefix() { const client=request.extend({prefixUrl:'https://fixed.example'}); return client('path'); }
export function localObject(url) { const got={post:custom}; return got.post(url); }
export function shadowed(request,url) { return request.post(url); }
export function replaced(url) { let client=request.extend({}); client=custom; return client(url); }
"#).unwrap();
    fs::write(
        root.join("cjs.js"),
        r#"
const got = /** @type {unknown} */ (require('got').default);
function commonjs(url) { return got.post(url); }
"#,
    )
    .unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    let sinks = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| {
            e.kind == EvidenceKind::Sink
                && e.capability == Capability::OutboundNetworkRequest
                && e.tags.iter().any(|t| t == "http-client:got")
        })
        .collect::<Vec<_>>();
    for name in [
        "direct",
        "streamed",
        "factory",
        "chained",
        "overridden",
        "hooked",
        "fixed",
        "fixedPrefix",
        "commonjs",
    ] {
        assert!(
            sinks
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(name)),
            "missing Got dispatch {name}: {sinks:#?}"
        );
    }
    for name in ["localObject", "shadowed", "replaced"] {
        assert!(
            !sinks
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(name)),
            "unrelated Got spelling {name}"
        );
    }
    let overridden = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("overridden"))
        .unwrap();
    assert_eq!(overridden.captures["endpoint"].text, "req.query.override");
    let factory = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("factory"))
        .unwrap();
    assert_eq!(factory.captures["endpoint"].text, "base");
    assert!(factory.captures.contains_key("http_client_0_definition"));
    for name in ["fixed", "fixedPrefix"] {
        let sink = sinks
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(name))
            .unwrap();
        assert!(
            !inventory
                .entries
                .iter()
                .any(|e| e.identity.as_ref().is_some_and(|i| i.anchor_id == sink.id)),
            "fixed ordinary request should not require a review: {name}"
        );
    }
    let hooked = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("hooked"))
        .unwrap();
    assert!(
        inventory.entries.iter().any(|e| e
            .identity
            .as_ref()
            .is_some_and(|i| i.anchor_id == hooked.id)),
        "fixed URL must not close custom hook destination question"
    );
    assert!(
        inventory.entries.iter().any(|e| e
            .identity
            .as_ref()
            .is_some_and(|i| i.anchor_id == hooked.id)
            && e.value_hint.is_some()),
        "unresolved options on fixed authority are research, not an automatic Value promotion"
    );
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Resource
                && e.rule_id == "javascript-http-client-factory")
    );
    fs::remove_dir_all(root).unwrap();
}
