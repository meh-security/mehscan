use mehscan_core::Capability;
use mehscan_engine::investigation::build_review_inventory;
use std::fs;

#[test]
fn imported_literal_destinations_and_explicit_data_schemas_are_context() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-node-constant-admission-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let files = [
        (
            "constants.ts",
            "export const BASE = 'https://service.example'; export let MUTABLE = 'https://service.example'; export const CONFIG = process.env.API_URL;",
        ),
        (
            "barrel.ts",
            "export { BASE as API, MUTABLE, CONFIG } from './constants';",
        ),
        (
            "fixed.ts",
            "import { API as target } from './barrel'; export async function handler(req:any) { return fetch(`${target}/token`, {method:'POST', body:JSON.stringify({code:req.query.code})}); }",
        ),
        (
            "dynamic.ts",
            "import { API } from './barrel'; export function handler(req:any) { return fetch(`${API}/${req.query.path}`); }",
        ),
        (
            "mutable.ts",
            "import { MUTABLE } from './barrel'; export function handler() { return fetch(MUTABLE); }",
        ),
        (
            "config.ts",
            "import { CONFIG } from './barrel'; export function handler() { return fetch(CONFIG); }",
        ),
        (
            "shadow.ts",
            "import { API } from './barrel'; export function handler(API:string) { return fetch(`${API}/token`); }",
        ),
        (
            "overridden.ts",
            "import { API } from './barrel'; export function handler(options:any) { return fetch(API, options); }",
        ),
        (
            "safe.ts",
            "import yaml from 'js-yaml'; export function parse(input:string) { return yaml.load(input, {schema:yaml.JSON_SCHEMA}); }",
        ),
        (
            "named.ts",
            "import {load, FAILSAFE_SCHEMA as DATA} from 'js-yaml'; export function parse(input:string) { return load(input, {schema:DATA}); }",
        ),
        (
            "custom.ts",
            "import yaml from 'js-yaml'; export function parse(input:string, schema:any) { return yaml.load(input, {schema}); }",
        ),
        (
            "spread.ts",
            "import yaml from 'js-yaml'; export function parse(input:string, options:any) { return yaml.load(input, {schema:yaml.JSON_SCHEMA,...options}); }",
        ),
        (
            "schema-shadow.ts",
            "import yaml from 'js-yaml'; export function parse(input:string, yaml:any) { return yaml.load(input, {schema:yaml.JSON_SCHEMA}); }",
        ),
        (
            "schema-write.ts",
            "import yaml from 'js-yaml'; yaml.JSON_SCHEMA = custom; export function parse(input:string) { return yaml.load(input, {schema:yaml.JSON_SCHEMA}); }",
        ),
        (
            "lookalike.ts",
            "import yaml from 'other-yaml'; export function parse(input:string) { return yaml.load(input, {schema:yaml.JSON_SCHEMA}); }",
        ),
    ];
    for (path, source) in files {
        fs::write(root.join(path), source).unwrap();
    }
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for (path, excluded, capability) in [
        ("fixed.ts", true, Capability::OutboundNetworkRequest),
        ("dynamic.ts", false, Capability::OutboundNetworkRequest),
        ("mutable.ts", false, Capability::OutboundNetworkRequest),
        ("config.ts", false, Capability::OutboundNetworkRequest),
        ("shadow.ts", false, Capability::OutboundNetworkRequest),
        ("overridden.ts", false, Capability::OutboundNetworkRequest),
        ("safe.ts", true, Capability::Deserialization),
        ("named.ts", true, Capability::Deserialization),
        ("custom.ts", false, Capability::Deserialization),
        ("spread.ts", false, Capability::Deserialization),
        ("schema-write.ts", false, Capability::Deserialization),
    ] {
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.location.path == path && e.capability == capability),
            "missing raw evidence: {path}"
        );
        assert_eq!(
            !inventory
                .entries
                .iter()
                .any(|e| e.path == path && e.capability == capability),
            excluded,
            "wrong admission: {path}: {:?}",
            inventory
                .scan
                .evidence
                .iter()
                .filter(|e| e.location.path == path && e.capability == capability)
                .collect::<Vec<_>>()
        );
    }
    // If a shadowed/lookalike API is still detected by a broad rule, this
    // optimization must not reinterpret its schema as a js-yaml guarantee.
    for path in ["schema-shadow.ts", "lookalike.ts"] {
        for e in inventory
            .scan
            .evidence
            .iter()
            .filter(|e| e.location.path == path && e.capability == Capability::Deserialization)
        {
            assert!(
                inventory
                    .entries
                    .iter()
                    .any(|r| r.identity.as_ref().is_some_and(|i| i.anchor_id == e.id)),
                "closed unrelated loader: {path}"
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}
