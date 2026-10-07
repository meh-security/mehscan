use mehscan_core::{Capability, OperandFactKind, SecurityPathState};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, source: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-node-operands-{label}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        for extension in ["js", "ts", "tsx"] {
            fs::write(root.join(format!("app.{extension}")), source).unwrap();
        }
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn local_query_objects_preserve_exact_operands_and_value_exceptions_in_all_node_profiles() {
    let source = r#"const {Client} = require('pg'); const client = new Client();
function fixed(value) { const config = {text: 'SELECT $1::text', values: [value]}; return client.query(config); }
function composed(value) { const config = {text: 'SELECT * FROM users WHERE id = ' + value, values: [value]}; return client.query(config); }
function mutated(value) { const config = {text: 'SELECT $1', values: [value]}; config.text = value; return client.query(config); }
function escaped(value) { const config = {text: 'SELECT $1', values: [value]}; modify(config); return client.query(config); }
function aliased(value) { const config = {text: 'SELECT $1', values: [value]}; const other = config; other.text = value; return client.query(config); }
function spread(value) { const config = {text: 'SELECT $1', values: [value], ...value}; return client.query(config); }
function computed(value, key) { const config = {text: 'SELECT $1', values: [value], [key]: value}; return client.query(config); }
function duplicate(value) { const config = {text: 'SELECT $1', values: [value], text: value}; return client.query(config); }
function getter(value) { const config = {get text() { return value; }, values: [value]}; return client.query(config); }
function two_hops(value) { const first = {text: 'SELECT $1', values: [value]}; const config = first; return client.query(config); }
function mutable(value) { let config = {text: 'SELECT $1', values: [value]}; return client.query(config); }
function nested(value) { const config = {text: 'SELECT $1', values: [value]}; return () => client.query(config); }
function extra_arguments(value) { const config = {text: 'SELECT $1', values: [value]}; return client.query(config, value); }
function input_cooccurrence(req) { const config = {text: 'SELECT $1', values: [req.query.id]}; return client.query(config); }
function inline_spread(value) { return client.query({text: 'SELECT $1', values: [value], ...value}); }
function inline_computed(value, key) { return client.query({text: 'SELECT $1', values: [value], [key]: value}); }
function inline_escaped_key(value) { return client.query({text: 'SELECT $1', values: [value], '\u0074ext': value}); }
"#;
    let fixture = Fixture::new("queries", source);
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, true).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for extension in ["js", "ts", "tsx"] {
        let path = format!("app.{extension}");
        let fixed = inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.location.path == path
                    && e.enclosing_symbol.as_deref() == Some("fixed")
                    && e.capability == Capability::DatabaseQuery
            })
            .unwrap();
        assert_eq!(
            fixed.captures["query"].text, "config",
            "The original sink operand must stay intact"
        );
        assert_eq!(fixed.captures["query_text"].text, "'SELECT $1::text'");
        assert_eq!(fixed.captures["query_values"].text, "[value]");
        for role in ["query_text", "query_values", "query_origin"] {
            let capture = &fixed.captures[role];
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
        let entry = inventory
            .entries
            .iter()
            .find(|e| e.path == path && e.symbol.as_deref() == Some("fixed"))
            .expect("Comprehensive ID retained");
        assert_eq!(
            entry.value_hint.as_ref().unwrap().reason,
            "local_bound_query_inventory"
        );
        for symbol in [
            "composed",
            "mutated",
            "escaped",
            "aliased",
            "spread",
            "computed",
            "duplicate",
            "getter",
            "two_hops",
            "mutable",
            "nested",
            "extra_arguments",
            "input_cooccurrence",
            "inline_spread",
            "inline_computed",
            "inline_escaped_key",
        ] {
            let entries = inventory
                .entries
                .iter()
                .filter(|e| e.path == path && e.symbol.as_deref() == Some(symbol))
                .collect::<Vec<_>>();
            assert!(
                !entries.is_empty(),
                "Lost consequential/uncertain {path}:{symbol}"
            );
            assert!(
                entries.iter().all(|entry| entry.value_hint.is_none()),
                "Deferred {path}:{symbol}"
            );
        }
        let mutation = inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.location.path == path
                    && e.enclosing_symbol.as_deref() == Some("mutated")
                    && e.capability == Capability::DatabaseQuery
            })
            .unwrap();
        let boundary = mutation
            .context
            .operand_facts
            .iter()
            .find(|f| f.kind == OperandFactKind::OperandBoundary)
            .unwrap();
        assert_eq!(boundary.value, "intervening_use_or_escape");
        assert_eq!(
            &source[boundary.location.start.byte_offset..boundary.location.end.byte_offset],
            "config"
        );
    }
}

#[test]
fn local_process_options_expose_shell_mode_and_keep_unsupported_options_reviewable() {
    let source = r#"const cp = require('node:child_process');
function shell(value) { const opts = {shell: true}; return cp.execFile('tool', [value], opts); }
function argumentsOnly(value) { const opts = {shell: false}; return cp.execFile('tool', [value], opts); }
function mutated(value) { const opts = {shell: false}; opts.shell = true; return cp.execFile('tool', [value], opts); }
function escaped(value) { const opts = {shell: false}; change(opts); return cp.execFile('tool', [value], opts); }
function spread(value) { const opts = {shell: false, ...value}; return cp.execFile('tool', [value], opts); }
function dynamic(value, options) { return cp.execFile('tool', [value], options); }
function factory(value) { const opts = optionsFactory(); return cp.execFile('tool', [value], opts); }
function direct_factory(value) { return cp.execFile('tool', [value], optionsFactory()); }
function custom_shell(value) { const opts = {shell: '/bin/sh'}; return cp.spawn('tool', [value], opts); }
function argument_escape(value) { const opts = {shell: false}; return cp.execFile('tool', [change(opts)], opts); }
function prototype(value) { const opts = {__proto__: value}; return cp.execFile('tool', [value], opts); }
"#;
    let fixture = Fixture::new("process", source);
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, true).unwrap();
    for extension in ["js", "ts", "tsx"] {
        let path = format!("app.{extension}");
        let sink = |name: &str| {
            inventory
                .scan
                .evidence
                .iter()
                .find(|e| {
                    e.location.path == path
                        && e.enclosing_symbol.as_deref() == Some(name)
                        && e.capability == Capability::ProcessExecution
                })
                .unwrap()
        };
        let shell = sink("shell");
        assert!(shell.tags.iter().any(|tag| tag == "shell-command-text"));
        assert_eq!(shell.captures["command"].text, "'tool'");
        assert_eq!(shell.captures["shell_command"].text, "[value]");
        assert!(
            shell
                .context
                .operand_facts
                .iter()
                .any(|fact| fact.kind == OperandFactKind::ProcessShellMode && fact.value == "true")
        );
        let arguments = sink("argumentsOnly");
        assert!(!arguments.tags.iter().any(|tag| tag == "shell-command-text"));
        assert!(arguments.context.operand_facts.iter().any(|fact| fact.kind == OperandFactKind::ProcessShellMode && fact.value == "false"));
        for name in [
            "shell",
            "mutated",
            "escaped",
            "spread",
            "dynamic",
            "factory",
            "direct_factory",
            "argument_escape",
            "prototype",
        ] {
            assert!(
                inventory
                    .entries
                    .iter()
                    .any(|entry| entry.path == path && entry.symbol.as_deref() == Some(name)),
                "Hidden shell option: {path}:{name}"
            );
            if name != "shell" {
                assert!(
                    sink(name)
                        .context
                        .operand_facts
                        .iter()
                        .any(|fact| fact.kind == OperandFactKind::OperandBoundary),
                    "Missing exact follow-up: {name}"
                );
                assert!(
                    !sink(name)
                        .context
                        .operand_facts
                        .iter()
                        .any(|fact| fact.kind == OperandFactKind::ProcessShellMode
                            && fact.value == "false"),
                    "Reused changed options: {name}"
                );
            }
        }
        assert!(
            sink("custom_shell")
                .tags
                .iter()
                .any(|tag| tag == "shell-command-text")
        );
        assert!(
            sink("custom_shell")
                .context
                .operand_facts
                .iter()
                .any(|fact| fact.kind == OperandFactKind::ProcessShellMode
                    && fact.value == "custom_shell")
        );
    }
}

#[test]
fn visible_query_method_replacement_vetoes_identity_based_deferral() {
    let source = "const {Client} = require('pg'); const client = new Client();\nclient.query = executeText;\nfunction fixed(value) { const config = {text: 'SELECT $1', values: [value]}; return client.query(config); }";
    let fixture = Fixture::new("receiver-write", source);
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, true).unwrap();
    for extension in ["js", "ts", "tsx"] {
        let entry = inventory
            .entries
            .iter()
            .find(|e| e.path == format!("app.{extension}") && e.symbol.as_deref() == Some("fixed"))
            .unwrap();
        assert!(entry.value_hint.is_none());
        let sink = inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.location.path == entry.path
                    && e.enclosing_symbol == entry.symbol
                    && e.capability == Capability::DatabaseQuery
            })
            .unwrap();
        assert!(
            sink.context
                .operand_facts
                .iter()
                .any(|fact| fact.kind == OperandFactKind::OperandBoundary
                    && fact.value == "observed_query_method_write")
        );
    }
}

#[test]
fn shell_options_override_structured_argv_protection_on_actual_input_paths() {
    let fixture = Fixture::new(
        "route-options",
        r#"const express = require('express');
const cp = require('node:child_process');
const app = express();
app.get('/shell', (req, res) => { const opts = {shell: true}; cp.execFile('tool', [req.query.value], opts); });
app.get('/argv', (req, res) => { const opts = {shell: false}; cp.execFile('tool', [req.query.value], opts); });
app.get('/changed', (req, res) => { const opts = {shell: false}; opts.shell = true; cp.execFile('tool', [req.query.value], opts); });
app.get('/factory', (req, res) => { cp.execFile('tool', [req.query.value], loadOptions()); });
"#,
    );
    let result = mehscan_engine::scan_path(&fixture.0).unwrap();
    for extension in ["js", "ts", "tsx"] {
        for (line, protected) in [(4, false), (5, true), (6, false), (7, false)] {
            let paths = result
                .security_paths
                .iter()
                .filter(|p| {
                    p.capability == Capability::ProcessExecution
                        && p.steps.last().is_some_and(|s| {
                            s.location.path == format!("app.{extension}")
                                && s.location.start.line == line
                        })
                })
                .collect::<Vec<_>>();
            assert!(!paths.is_empty(), "Missing process path {extension}:{line}");
            assert!(
                paths
                    .iter()
                    .all(|p| (p.state == SecurityPathState::Protected) == protected),
                "Contradictory shell protection {extension}:{line}: {paths:?}"
            );
        }
    }
}
