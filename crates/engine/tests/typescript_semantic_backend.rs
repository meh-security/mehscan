//! Real compiler contract: imported navigation, exact identity preservation and cache invalidation.
use mehscan_core::OperandFactKind;
use mehscan_engine::{investigation, typescript_semantic as ts};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

struct Fixture {
    root: PathBuf,
    context: PathBuf,
}
impl Fixture {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-typescript-{label}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typescript-semantic");
        for file in ["app.ts", "helpers.ts", "driver.ts"] {
            fs::copy(source.join(file), root.join(file)).unwrap();
        }
        let context = root.join("context.json");
        fs::write(&context, serde_json::to_vec(&json!({"typescript_path": std::env::var("MEHSCAN_TYPESCRIPT_COMPILER").unwrap(),
            "projects": [{"id": "web", "sources": ["app.ts", "helpers.ts", "driver.ts"], "compiler_options": {"target": "ES2022", "module": "commonjs", "strict": true}}]})).unwrap()).unwrap();
        Self { root, context }
    }
    fn backend(&self) -> PathBuf {
        std::env::var("MEHSCAN_TYPESCRIPT_BACKEND").unwrap().into()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
#[ignore = "requires Node and MEHSCAN_TYPESCRIPT_BACKEND / MEHSCAN_TYPESCRIPT_COMPILER"]
fn incoming_parameter_navigation_preserves_queue_and_binds_caller_source() {
    let fixture = Fixture::new("incoming");
    fs::write(fixture.root.join("app.ts"),
        "import {readFileSync} from 'node:fs'; export function read(value: string) { return readFileSync(value); }").unwrap();
    fs::write(fixture.root.join("driver.ts"),
        "import {read as selected} from './app'; declare const requestPath: string; selected(requestPath);").unwrap();
    let baseline = mehscan_engine::scan_path(&fixture.root).unwrap();
    let snapshot = ts::collect(
        &fixture.root,
        &fixture.context,
        &fixture.backend(),
        &baseline,
    )
    .unwrap();
    let mut enriched = baseline.clone();
    ts::enrich(&fixture.root, &fixture.context, &snapshot, &mut enriched).unwrap();
    let incoming = enriched
        .evidence
        .iter()
        .flat_map(|e| &e.context.operand_facts)
        .find(|f| {
            f.kind == OperandFactKind::LocalCallArgument
                && f.location.path == "driver.ts"
                && f.value == "requestPath"
        })
        .unwrap();
    assert!(
        incoming
            .remaining_checks
            .iter()
            .any(|c| c == "caller_scope_is_supplied_project")
    );
    assert_eq!(baseline.security_paths, enriched.security_paths);
    let plain = investigation::build_review_inventory(&fixture.root, false).unwrap();
    let native = investigation::build_review_inventory_with_native_backends(
        &fixture.root,
        false,
        None,
        None,
        Some(ts::Input::Backend(&fixture.context, &fixture.backend())),
        None,
    )
    .unwrap();
    assert_eq!(
        plain
            .entries
            .iter()
            .map(|e| (&e.review_id, serde_json::to_value(&e.value_hint).unwrap()))
            .collect::<Vec<_>>(),
        native
            .entries
            .iter()
            .map(|e| (&e.review_id, serde_json::to_value(&e.value_hint).unwrap()))
            .collect::<Vec<_>>()
    );
    fs::write(
        fixture.root.join("driver.ts"),
        "import {read} from './app'; read('changed');",
    )
    .unwrap();
    assert!(
        ts::enrich(
            &fixture.root,
            &fixture.context,
            &snapshot,
            &mut baseline.clone()
        )
        .is_err()
    );
}

#[test]
#[ignore = "requires Node and MEHSCAN_TYPESCRIPT_BACKEND / MEHSCAN_TYPESCRIPT_COMPILER"]
fn ordinary_browser_requests_leave_both_queues_and_consequential_requests_remain() {
    let fixture = Fixture::new("browser");
    fs::write(fixture.root.join("browser.ts"), r#"
export function ordinary(url: string) { return fetch(url); }
export function head(url: string) { return fetch(url, {method: 'HEAD'}); }
export function bearer(url: string) { return fetch(url, {headers: {Authorization: 'Bearer token'}}); }
export function mutate(url: string) { return fetch(url, {method: 'POST'}); }
export function options(url: string, init: RequestInit) { return fetch(url, init); }
export function connected(req: any) { return fetch(req.query.url); }
"#).unwrap();
    fs::write(
        fixture.root.join("links.tsx"),
        r#"
export function Linked(url: string) { return <a href={url}>link</a>; }
export function caller(storedUrl: string) { return Linked(storedUrl); }
"#,
    )
    .unwrap();
    let context = json!({"typescript_path": std::env::var("MEHSCAN_TYPESCRIPT_COMPILER").unwrap(),
        "projects": [{"id": "browser", "runtime": "browser", "sources": ["browser.ts", "links.tsx"],
            "compiler_options": {"target": "ES2022", "module": "commonjs", "jsx": "preserve", "strict": true}}]});
    fs::write(&fixture.context, serde_json::to_vec(&context).unwrap()).unwrap();
    let baseline = investigation::build_review_inventory(&fixture.root, true).unwrap();
    let native = investigation::build_review_inventory_with_native_backends(
        &fixture.root,
        true,
        None,
        None,
        Some(ts::Input::Backend(&fixture.context, &fixture.backend())),
        None,
    )
    .unwrap();
    for name in ["ordinary", "head"] {
        assert!(
            baseline
                .entries
                .iter()
                .any(|entry| entry.path == "browser.ts" && entry.symbol.as_deref() == Some(name)),
            "unknown runtime must retain {name}"
        );
        assert!(
            !native
                .entries
                .iter()
                .any(|e| e.path == "browser.ts" && e.symbol.as_deref() == Some(name)),
            "ordinary DOM request has no standalone SSRF question: {name}"
        );
    }
    for name in ["bearer", "mutate", "options", "connected"] {
        let entries = native
            .entries
            .iter()
            .filter(|e| e.path == "browser.ts" && e.symbol.as_deref() == Some(name))
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "must contain {name}");
        assert!(
            entries.iter().all(|e| e.value_hint.is_none()),
            "must keep {name}"
        );
    }
    let linked = native
        .entries
        .iter()
        .find(|entry| entry.path == "links.tsx" && entry.symbol.as_deref() == Some("Linked"))
        .expect("observed caller arguments must preserve the URL writer question");
    assert!(linked.value_hint.is_none());
    assert!(native.scan.evidence.iter().any(|item| {
        item.location.path == "links.tsx"
            && item.enclosing_symbol.as_deref() == Some("Linked")
            && item
                .context
                .operand_facts
                .iter()
                .any(|fact| fact.kind == OperandFactKind::LocalCallArgument)
    }));
    let scan = mehscan_engine::scan_path(&fixture.root).unwrap();
    let snapshot = ts::collect(&fixture.root, &fixture.context, &fixture.backend(), &scan).unwrap();
    let mut server = context;
    server["projects"][0]["runtime"] = json!("server");
    fs::write(&fixture.context, serde_json::to_vec(&server).unwrap()).unwrap();
    let mut stale = scan;
    assert!(ts::enrich(&fixture.root, &fixture.context, &snapshot, &mut stale).is_err());
}

#[test]
#[ignore = "requires Node and MEHSCAN_TYPESCRIPT_BACKEND / MEHSCAN_TYPESCRIPT_COMPILER"]
fn native_navigation_is_source_bound_and_cached_without_changing_ids() {
    let fixture = Fixture::new("navigation");
    let baseline = mehscan_engine::scan_path(&fixture.root).unwrap();
    assert_eq!(
        ts::queries(&baseline)
            .iter()
            .map(|q| q.role.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["query", "path", "command", "content"])
    );
    let snapshot = ts::collect(
        &fixture.root,
        &fixture.context,
        &fixture.backend(),
        &baseline,
    )
    .unwrap();
    assert!(!snapshot.observations.is_empty());
    let mut enriched = baseline.clone();
    ts::enrich(&fixture.root, &fixture.context, &snapshot, &mut enriched).unwrap();
    assert_eq!(baseline.security_paths, enriched.security_paths);
    assert_eq!(
        baseline.evidence.iter().map(|e| &e.id).collect::<Vec<_>>(),
        enriched.evidence.iter().map(|e| &e.id).collect::<Vec<_>>()
    );
    let facts = enriched
        .evidence
        .iter()
        .flat_map(|e| &e.context.operand_facts)
        .collect::<Vec<_>>();
    assert!(
        facts
            .iter()
            .any(|f| f.kind == OperandFactKind::SemanticDefinition
                && f.location.path == "helpers.ts"),
        "queries={} observations={}",
        serde_json::to_string(&ts::queries(&baseline)).unwrap(),
        serde_json::to_string(&snapshot.observations).unwrap()
    );
    assert!(
        facts
            .iter()
            .any(|f| f.kind == OperandFactKind::LocalOperandOrigin
                && f.location.path == "helpers.ts")
    );
    assert!(facts.iter().all(|f| !matches!(
        f.kind,
        OperandFactKind::FixedFilesystemPath | OperandFactKind::EncodedHtmlOperand
    )));
    assert!(
        !serde_json::to_string(&facts)
            .unwrap()
            .contains(&fixture.root.to_string_lossy().replace('\\', "/"))
    );
    let plain = investigation::build_review_inventory(&fixture.root, false).unwrap();
    let cached = investigation::build_review_inventory_with_native_backends(
        &fixture.root,
        false,
        None,
        None,
        Some(ts::Input::Backend(&fixture.context, &fixture.backend())),
        None,
    )
    .unwrap();
    assert_eq!(
        plain
            .entries
            .iter()
            .map(|e| (&e.review_id, serde_json::to_value(&e.value_hint).unwrap()))
            .collect::<Vec<_>>(),
        cached
            .entries
            .iter()
            .map(|e| (&e.review_id, serde_json::to_value(&e.value_hint).unwrap()))
            .collect::<Vec<_>>()
    );
    assert_ne!(
        plain.input_fingerprint().unwrap(),
        cached.input_fingerprint().unwrap()
    );
    let selected = cached
        .entries
        .iter()
        .filter(|e| {
            e.operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::SemanticDefinition)
        })
        .map(|e| e.review_id.clone())
        .collect::<BTreeSet<_>>();
    assert!(!selected.is_empty());
    let job = investigation::build_selected_review_jobs(&fixture.root, &cached, &selected, Some(2))
        .unwrap();
    assert!(job.fingerprint.starts_with("path-reviewpack-"));
    // Stale dependency source invalidates both snapshot import and cached selected cards.
    fs::write(fixture.root.join("helpers.ts"), "export function makeQuery(value: string) { return value; }\nexport function makePath(value: string) { return value; }").unwrap();
    assert!(
        ts::enrich(&fixture.root, &fixture.context, &snapshot, &mut enriched)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
    assert!(
        investigation::build_selected_review_jobs(&fixture.root, &cached, &selected, Some(2))
            .is_err()
    );
}

#[test]
#[ignore = "requires Node and MEHSCAN_TYPESCRIPT_BACKEND / MEHSCAN_TYPESCRIPT_COMPILER"]
fn overlapping_contexts_unknown_types_and_tampering_cannot_upgrade_facts() {
    let fixture = Fixture::new("unknown");
    fs::write(fixture.root.join("helpers.ts"), "export declare function makeQuery(value: string): any;\nexport declare function makePath(value: string): any;").unwrap();
    let baseline = mehscan_engine::scan_path(&fixture.root).unwrap();
    let snapshot = ts::collect(
        &fixture.root,
        &fixture.context,
        &fixture.backend(),
        &baseline,
    )
    .unwrap();
    assert!(
        snapshot
            .observations
            .iter()
            .flat_map(|o| &o.facts)
            .any(|f| f.kind == OperandFactKind::OperandBoundary
                && f.value == "unresolved_or_dynamic_type")
    );
    assert!(
        !snapshot
            .observations
            .iter()
            .flat_map(|o| &o.facts)
            .any(|f| f.kind == OperandFactKind::LocalOperandOrigin
                && f.location.path == "helpers.ts")
    );
    let mut altered = serde_json::to_value(&snapshot).unwrap();
    altered["observations"][0]["facts"][0]["kind"] = json!("fixed_filesystem_path");
    let altered: ts::Snapshot = serde_json::from_value(altered).unwrap();
    assert!(
        ts::enrich(
            &fixture.root,
            &fixture.context,
            &altered,
            &mut baseline.clone()
        )
        .is_err()
    );
    let mut context: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.context).unwrap()).unwrap();
    let mut second = context["projects"][0].clone();
    second["id"] = json!("second");
    context["projects"].as_array_mut().unwrap().push(second);
    fs::write(&fixture.context, serde_json::to_vec(&context).unwrap()).unwrap();
    let snapshot = ts::collect(
        &fixture.root,
        &fixture.context,
        &fixture.backend(),
        &baseline,
    )
    .unwrap();
    let mut enriched = baseline.clone();
    ts::enrich(&fixture.root, &fixture.context, &snapshot, &mut enriched).unwrap();
    assert_eq!(baseline.evidence, enriched.evidence);
    assert!(
        enriched
            .diagnostics
            .iter()
            .any(|d| d.message.contains("overlapping"))
    );
}

#[test]
#[ignore = "requires Node and MEHSCAN_TYPESCRIPT_BACKEND / MEHSCAN_TYPESCRIPT_COMPILER"]
fn inherited_config_and_static_node_paths_reduce_only_complete_traversal_questions() {
    let fixture = Fixture::new("static-node");
    fs::write(fixture.root.join("app.ts"), "import fs from 'node:fs';\nimport path from 'node:path';\nimport {fixedRoot, makePath} from '@helpers';\nexport function fixedRead() { return fs.readFileSync(path.resolve(fixedRoot, 'legal.md')); }\nexport function helperRead() { return fs.readFileSync(makePath('legal.md')); }\nexport function helperInput(req: any) { return fs.readFileSync(makePath(req.query.file)); }\nexport function inputRead(req: any) { return fs.readFileSync(path.resolve(fixedRoot, req.query.file)); }\n").unwrap();
    fs::write(
        fixture.root.join("helpers.ts"),
        "export const fixedRoot = 'storage';\nexport function makePath(value: string) { return fixedRoot + '/' + value; }\n",
    )
    .unwrap();
    fs::write(fixture.root.join("base.json"), "{\"compilerOptions\":{\"baseUrl\":\".\",\"paths\":{\"@helpers\":[\"helpers.ts\"]},\"esModuleInterop\":true}}").unwrap();
    fs::write(
        fixture.root.join("tsconfig.json"),
        "{\"extends\":\"./base.json\"}",
    )
    .unwrap();
    let mut context: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.context).unwrap()).unwrap();
    let compiler = PathBuf::from(std::env::var("MEHSCAN_TYPESCRIPT_COMPILER").unwrap());
    context["node_types"] = json!(
        compiler
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("@types/node")
    );
    context["projects"][0]["tsconfig"] = json!("tsconfig.json");
    fs::write(&fixture.context, serde_json::to_vec(&context).unwrap()).unwrap();
    let plain = investigation::build_review_inventory(&fixture.root, false).unwrap();
    let native = investigation::build_review_inventory_with_native_backends(
        &fixture.root,
        false,
        None,
        None,
        Some(ts::Input::Backend(&fixture.context, &fixture.backend())),
        None,
    )
    .unwrap();
    let removed = plain
        .entries
        .iter()
        .filter(|e| !native.entries.iter().any(|n| n.review_id == e.review_id))
        .collect::<Vec<_>>();
    assert!(!removed.is_empty());
    assert!(
        removed
            .iter()
            .all(|e| matches!(e.symbol.as_deref(), Some("fixedRead" | "helperRead")))
    );
    assert!(
        removed
            .iter()
            .any(|e| e.symbol.as_deref() == Some("helperRead"))
    );
    assert!(
        native
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("helperInput"))
    );
    assert!(
        native
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("inputRead"))
    );
    assert_eq!(plain.scan.security_paths, native.scan.security_paths);
    assert!(
        native
            .scan
            .evidence
            .iter()
            .flat_map(|e| &e.context.operand_facts)
            .any(|f| f.kind == OperandFactKind::FixedFilesystemPath
                && !f
                    .remaining_checks
                    .iter()
                    .any(|c| c == "partial_semantic_context"))
    );
    let selected = native.entries.iter().map(|e| e.review_id.clone()).collect();
    assert!(
        investigation::build_selected_review_jobs(&fixture.root, &native, &selected, Some(2))
            .is_ok()
    );
    fs::write(
        fixture.root.join("base.json"),
        "{\"compilerOptions\":{\"baseUrl\":\"elsewhere\"}}",
    )
    .unwrap();
    assert!(
        investigation::build_selected_review_jobs(&fixture.root, &native, &selected, Some(2))
            .is_err()
    );
}

#[test]
#[ignore = "requires Node and MEHSCAN_TYPESCRIPT_BACKEND / MEHSCAN_TYPESCRIPT_COMPILER"]
fn missing_module_appearance_and_compiler_metadata_changes_invalidate_snapshot() {
    let fixture = Fixture::new("resolution");
    let config = fixture.root.join("project-options.json");
    fs::write(&config, "{}").unwrap();
    let mut context: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.context).unwrap()).unwrap();
    context["context_files"] = json!([config]);
    fs::write(&fixture.context, serde_json::to_vec(&context).unwrap()).unwrap();
    fs::write(
        fixture.root.join("helpers.ts"),
        "export { makeQuery, makePath } from './missing';",
    )
    .unwrap();
    let baseline = mehscan_engine::scan_path(&fixture.root).unwrap();
    let snapshot = ts::collect(
        &fixture.root,
        &fixture.context,
        &fixture.backend(),
        &baseline,
    )
    .unwrap();
    let mut missing_input = serde_json::to_value(&snapshot).unwrap();
    missing_input["inputs"]
        .as_array_mut()
        .unwrap()
        .retain(|input| {
            !input["path"]
                .as_str()
                .unwrap()
                .ends_with("project-options.json")
        });
    let missing_input: ts::Snapshot = serde_json::from_value(missing_input).unwrap();
    assert!(
        ts::enrich(
            &fixture.root,
            &fixture.context,
            &missing_input,
            &mut baseline.clone()
        )
        .unwrap_err()
        .to_string()
        .contains("context file input is missing")
    );
    fs::write(
        fixture.root.join("missing.ts"),
        "export const makeQuery = (x: string) => x; export const makePath = makeQuery;",
    )
    .unwrap();
    assert!(
        ts::enrich(
            &fixture.root,
            &fixture.context,
            &snapshot,
            &mut baseline.clone()
        )
        .unwrap_err()
        .to_string()
        .contains("resolution is stale")
    );
    let mut altered = serde_json::to_value(&snapshot).unwrap();
    altered["inputs"][0]["sha256"] = json!("invalid");
    let altered: ts::Snapshot = serde_json::from_value(altered).unwrap();
    assert!(
        ts::enrich(
            &fixture.root,
            &fixture.context,
            &altered,
            &mut baseline.clone()
        )
        .unwrap_err()
        .to_string()
        .contains("input is stale")
    );
}
