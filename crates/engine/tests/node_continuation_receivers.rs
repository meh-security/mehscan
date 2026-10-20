use mehscan_core::{Capability, EvidenceKind};
use std::fs;

#[test]
fn callback_slots_and_owned_template_receivers_keep_only_proved_flows() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-continuation-receivers-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("helpers.js"), r#"
import {Environment as View, configure as setup} from 'nunjucks';
import * as rendering from 'nunjucks';
const views = new View();
export function forward(value, cb) { cb(null, value); }
export function direct(value, cb) { cb(value); }
export function clean(value, cb) { cb(null, 'safe'); }
export function changed(value, cb) { value='safe'; cb(null, value); }
export function replaced(value, cb) { cb=other; cb(null, value); }
export function error(value, cb) { cb(value, 'safe'); }
export function template(value) { return views.renderString(value); }
export function local(value) { const engine = setup(); return engine.renderString(value); }
export function data(value) { return views.renderString('Hello {{name}}', value); }
export function shadow(value, views) { return views.renderString(value); }
export function unrelated(value) { const engine = new Other(); return engine.renderString(value); }
export function nested(value) { return views.other.renderString(value); }
export function reset(value) { const engine = new View(); engine.renderString=other; return engine.renderString(value); }
export function otherObject(value) { const engine = new View(); const cleanEngine = new Other(); return cleanEngine.renderString(value); }
export function constructorShadow(value, rendering) { const engine = new rendering . Environment(); return engine.renderString(value); }
"#).unwrap();
    let cases = [
        (
            "errorFirst",
            "forward(req.query.value, (err, value) => eval(value));",
            true,
            Capability::DynamicCodeExecution,
        ),
        (
            "direct",
            "direct(req.query.value, value => eval(value));",
            true,
            Capability::DynamicCodeExecution,
        ),
        (
            "errorSlot",
            "forward(req.query.value, (err, value) => eval(err));",
            false,
            Capability::DynamicCodeExecution,
        ),
        (
            "clean",
            "clean(req.query.value, (err, value) => eval(value));",
            false,
            Capability::DynamicCodeExecution,
        ),
        (
            "changed",
            "changed(req.query.value, (err, value) => eval(value));",
            false,
            Capability::DynamicCodeExecution,
        ),
        (
            "replaced",
            "replaced(req.query.value, (err, value) => eval(value));",
            false,
            Capability::DynamicCodeExecution,
        ),
        (
            "error",
            "error(req.query.value, (err, value) => eval(value));",
            false,
            Capability::DynamicCodeExecution,
        ),
        (
            "callbackOverwrite",
            "forward(req.query.value, (err, value) => { value='safe'; eval(value); });",
            false,
            Capability::DynamicCodeExecution,
        ),
        (
            "promise",
            "Promise.resolve(req.query.value).then(value => eval(value));",
            true,
            Capability::DynamicCodeExecution,
        ),
        (
            "promiseOverwrite",
            "Promise.resolve(req.query.value).then(value => { value='safe'; eval(value); });",
            false,
            Capability::DynamicCodeExecution,
        ),
        (
            "promiseShadow",
            "const Promise=other; Promise.resolve(req.query.value).then(value => eval(value));",
            false,
            Capability::DynamicCodeExecution,
        ),
        (
            "functionShadow",
            "function forward(value, cb) { cb(null, 'safe'); } forward(req.query.value, (err, value) => eval(value));",
            false,
            Capability::DynamicCodeExecution,
        ),
        (
            "template",
            "template(req.query.value);",
            true,
            Capability::TemplateEvaluation,
        ),
        (
            "local",
            "local(req.query.value);",
            true,
            Capability::TemplateEvaluation,
        ),
        (
            "data",
            "data(req.query.value);",
            false,
            Capability::TemplateEvaluation,
        ),
        (
            "shadow",
            "shadow(req.query.value, other);",
            false,
            Capability::TemplateEvaluation,
        ),
        (
            "unrelated",
            "unrelated(req.query.value);",
            false,
            Capability::TemplateEvaluation,
        ),
        (
            "nested",
            "nested(req.query.value);",
            false,
            Capability::TemplateEvaluation,
        ),
        (
            "reset",
            "reset(req.query.value);",
            false,
            Capability::TemplateEvaluation,
        ),
        (
            "otherObject",
            "otherObject(req.query.value);",
            false,
            Capability::TemplateEvaluation,
        ),
        (
            "constructorShadow",
            "constructorShadow(req.query.value, other);",
            false,
            Capability::TemplateEvaluation,
        ),
    ];
    let imports = "import {forward,direct,clean,changed,replaced,error,template,local,data,shadow,unrelated,nested,reset,otherObject,constructorShadow} from './helpers.js';";
    for (index, (name, body, _, _)) in cases.iter().enumerate() {
        let extension = ["js", "ts", "tsx"][index % 3];
        let annotation = if extension == "js" { "" } else { ":any" };
        fs::write(
            root.join(format!("{name}.{extension}")),
            format!("{imports}\nexport function handle(req{annotation}) {{ {body} }}"),
        )
        .unwrap();
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    for (index, (name, _, expected, capability)) in cases.iter().enumerate() {
        let path = format!("{name}.{}", ["js", "ts", "tsx"][index % 3]);
        let found = scan.security_paths.iter().any(|p| {
            p.capability == *capability && p.steps.last().is_some_and(|s| s.location.path == path)
        });
        assert_eq!(found, *expected, "wrong flow admission for {path}");
    }
    assert!(scan.evidence.iter().any(|e| {
        e.kind == EvidenceKind::Source
            && e.location.path.starts_with("errorFirst.")
            && e.tags.iter().any(|t| t == "callback-result-index:1")
            && e.captures
                .get("origin")
                .is_some_and(|c| c.text == "req.query.value")
    }));
    fs::remove_dir_all(root).unwrap();
}
