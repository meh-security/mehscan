use mehscan_core::{Capability, RuntimeEnvironment};
use std::fs;

#[test]
fn exact_http_effects_survive_package_aliases_and_controlled_workspace_helpers() {
    let root = std::env::temp_dir().join(format!("mehscan-http-effects-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("client.ts"),
        r#"
import network from 'node-fetch';
export default async function dispatch(url: string, options?: RequestInit) {
  if (!url) throw Error('missing');
  try { return await network(url, {...options, redirect:'manual'}); }
  finally { cleanup(); }
}
export function wiped(url: string) { url='https://fixed.example'; return network(url); }
export function unrelated(url: string) { return url; }
export function shadowed(url: string, network: (s: string)=>string) { return network(url); }
export function destructured({url}: {url: string}) { return network(url); }
"#,
    )
    .unwrap();
    fs::write(
        root.join("server.ts"),
        r#"
import fetch, {wiped, unrelated, shadowed, destructured} from './client';
import {fetch as remote} from 'undici';
export function handler(input: string) { return fetch(input, {redirect:'manual'}); }
export function renamed(input: string) { return remote(input); }
export function importedData(input: string) { return unrelated(input); }
export function overwritten(input: string) { return wiped(input); }
export function shadowedConsumer(fetch: (s:string)=>number,input:string) { return fetch(input); }
export function negativeShadow(input:string) { return shadowed(input, x=>x); }
export function negativeObject(input: string) { return destructured({url:input}); }
"#,
    )
    .unwrap();
    fs::write(root.join("alias.ts"), "import request from './client'; export function aliased(input:string) { return request(input); }\n").unwrap();
    fs::write(root.join("common.cjs"), "const download=require('node-fetch'); const {fetch: request}=require('undici'); function cjsAlias(url) { return download(url); } function cjsNamed(url) { return request(url); }\n").unwrap();
    fs::write(
        root.join("browser.ts"),
        r#"
function local(location: string) { window.location.href = String(location?.search(/^https?:/)); }
function localDocument(document: {URL: string}) { window.location.href = document.URL; }
function actual() { window.location.href = location.search + window.location.hash + document.referrer; }
function navigation(input:string) { window.location.href=input; }
"#,
    )
    .unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    let outgoing = scan
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::OutboundNetworkRequest)
        .collect::<Vec<_>>();
    for symbol in [
        "dispatch", "handler", "renamed", "aliased", "cjsAlias", "cjsNamed",
    ] {
        assert!(
            outgoing
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(symbol)),
            "missing {symbol}: {outgoing:#?}"
        );
    }
    for symbol in [
        "importedData",
        "overwritten",
        "shadowedConsumer",
        "negativeShadow",
        "negativeObject",
        "shadowed",
    ] {
        assert!(
            !outgoing
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(symbol)),
            "invented HTTP {symbol}: {outgoing:#?}"
        );
    }
    let handler = outgoing
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("handler"))
        .unwrap();
    assert!(handler.captures.contains_key("http_helper_definition"));
    assert!(handler.captures.contains_key("http_primitive_0_definition"));
    assert!(
        handler
            .tags
            .iter()
            .any(|t| t == "http-effect:reachability-and-controls-unproved")
    );
    assert_eq!(
        handler.context.runtime_environment,
        Some(RuntimeEnvironment::Unknown)
    );
    assert_eq!(
        outgoing
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some("handler"))
            .count(),
        1
    );
    let sources = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id.ends_with("-browser-url-source"))
        .collect::<Vec<_>>();
    assert!(
        sources
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("actual"))
    );
    assert!(!sources.iter().any(|e| matches!(
        e.enclosing_symbol.as_deref(),
        Some("local" | "localDocument")
    )));
    assert!(
        scan.evidence
            .iter()
            .any(|e| e.capability == Capability::BrowserNavigation
                && e.enclosing_symbol.as_deref() == Some("navigation"))
    );
    fs::remove_dir_all(root).unwrap();
}
