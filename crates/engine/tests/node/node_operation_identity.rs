use mehscan_core::Capability;
use std::fs;

#[test]
fn platform_names_respect_lexical_bindings_without_losing_http_delegation() {
    let root = std::env::temp_dir().join(format!("mehscan-node-identity-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("app.ts"),r#"
type Fetch = (url: string, init?: RequestInit) => Promise<Response>;
type Options = { endpoint: URL; fetch: typeof globalThis.fetch; };
function namedOptions({endpoint,fetch}: Options) { return fetch(endpoint); }
function globalRequest(url: string) { return fetch(url); }
function dataCallback(fetch: (fields: string[]) => Promise<Record<string, unknown>>, fields: string[]) { return fetch(fields); }
function inherited(fetch: () => Promise<number>) { return () => fetch(); }
function localFunction(url: string) { function fetch(x: string) { return x; } return fetch(url); }
function localObject(url: string) { const {fetch} = service; return fetch(url); }
function delegated(url: string, {fetch}: {fetch: Fetch}) { return fetch(url); }
function typedCallback(url: string, fetch: (url: string) => Promise<Response>) { return fetch(url); }
function qualifiedAlias(url: string) { const fetch = globalThis.fetch; return fetch(url); }
function localNavigation(location: string) { location = location.trim(); }
function blockNavigation(next: string) { { let location = ''; location = next; } }
function realNavigation(next: string) { location = next; }
function explicitNavigation(next: string, location: string) { window.location.href = next; }
"#).unwrap();
    fs::write(
        root.join("commonjs.js"),
        "const fetch = require('node-fetch'); function commonjs(url) { return fetch(url); }",
    )
    .unwrap();
    fs::write(
        root.join("undici.js"),
        "const {fetch} = require('undici'); function undiciImported(url) { return fetch(url); }",
    )
    .unwrap();
    fs::write(
        root.join("imported.ts"),
        r#"
import fetch from 'node-fetch';
export function imported(url: string) { return fetch(url); }
export function shadowed(fetch: (x: number) => number, x: number) { return fetch(x); }
"#,
    )
    .unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    let outbound = scan
        .evidence
        .iter()
        .filter(|e| {
            e.capability == Capability::OutboundNetworkRequest
                && e.rule_id.ends_with("-outbound-http")
        })
        .collect::<Vec<_>>();
    for name in [
        "globalRequest",
        "delegated",
        "typedCallback",
        "namedOptions",
        "qualifiedAlias",
        "imported",
        "commonjs",
        "undiciImported",
    ] {
        assert!(
            outbound
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(name)),
            "lost actual HTTP interface {name}: {outbound:#?}"
        );
    }
    for name in [
        "dataCallback",
        "inherited",
        "localFunction",
        "localObject",
        "shadowed",
    ] {
        assert!(
            !outbound
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(name)),
            "invented builtin HTTP {name}"
        );
    }
    let navigation = scan
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::BrowserNavigation)
        .collect::<Vec<_>>();
    for name in ["realNavigation", "explicitNavigation"] {
        assert!(
            navigation
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(name)),
            "lost browser navigation {name}"
        );
    }
    for name in ["localNavigation", "blockNavigation"] {
        assert!(
            !navigation
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(name)),
            "invented browser navigation {name}"
        );
    }
    fs::remove_dir_all(root).unwrap();
}
