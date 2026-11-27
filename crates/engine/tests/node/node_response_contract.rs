use mehscan_core::{Capability, OperandFactKind};
use mehscan_engine::investigation::build_review_inventory;
use std::fs;

#[test]
fn response_summaries_preserve_only_complete_stable_plain_text_contracts() {
    let root =
        std::env::temp_dir().join(format!("mehscan-response-contract-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("output.mjs"), r#"
export function prepare(reply) {
  reply.setHeader('X-Content-Type-Options', 'nosniff');
  reply.contentType('text/plain; charset=utf-8');
}
export function safe(reply, content) { prepare(reply); reply.send(content); }
export function direct(reply, content) {
  reply.set('Content-Type', 'text/plain');
  reply.header('X-Content-Type-Options', 'nosniff');
  return reply.send(content);
}
export function overridden(reply, content) { prepare(reply); reply.type('text/html'); reply.send(content); }
export function unresolved(reply, content) { prepare(reply); alter(reply); reply.send(content); }
export function conditional(reply, content) { if (content) prepare(reply); reply.send(content); }
export function wrongReceiver(reply, content, other) { prepare(other); reply.send(content); }
export function shadowed(reply, content, prepare) { prepare(reply); reply.send(content); }
async function asyncPrepare(reply) { reply.type('text/plain'); reply.setHeader('X-Content-Type-Options','nosniff'); }
export function asynchronous(reply, content) { asyncPrepare(reply); reply.send(content); }
function replaceable(reply) { reply.type('text/plain'); reply.setHeader('X-Content-Type-Options','nosniff'); }
function reconfigure() { replaceable = arbitrary; }
export function reassigned(reply, content) { replaceable(reply); reply.send(content); }
function destructuredPrepare({reply}) { reply.type('text/plain'); reply.setHeader('X-Content-Type-Options','nosniff'); }
export function destructured(reply, content) { destructuredPrepare(reply); reply.send(content); }
export function ordinary(reply, content) { reply.send(content); }
"#).unwrap();
    fs::write(root.join("app.mjs"), r#"
import {safe as text, direct, overridden, unresolved, conditional, wrongReceiver, shadowed, asynchronous, reassigned, destructured, ordinary} from './output.mjs';
export function run(req, res) {
  text(res, req.body);
  direct(res, req.body);
  overridden(res, req.body);
  unresolved(res, req.body);
  conditional(res, req.body);
  wrongReceiver(res, req.body, other);
  shadowed(res, req.body, arbitrary);
  asynchronous(res, req.body);
  reassigned(res, req.body);
  destructured(res, req.body);
  ordinary(res, req.body);
}
"#).unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    for helper in [
        "safe",
        "direct",
        "overridden",
        "unresolved",
        "wrongReceiver",
        "shadowed",
        "asynchronous",
        "reassigned",
        "destructured",
        "ordinary",
    ] {
        let evidence = inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.location.path == "app.mjs"
                    && e.rule_id == "javascript-parameter-sink-summary"
                    && e.capability == Capability::HtmlOutput
                    && e.captures
                        .get("helper_definition")
                        .is_some_and(|c| c.text == helper)
            })
            .unwrap_or_else(|| panic!("missing raw helper effect {helper}"));
        let closed = evidence
            .context
            .operand_facts
            .iter()
            .any(|f| f.kind == OperandFactKind::NonHtmlResponse);
        assert_eq!(
            closed,
            matches!(helper, "safe" | "direct"),
            "incorrect contract for {helper}"
        );
        let admitted = inventory.entries.iter().any(|e| {
            e.identity
                .as_ref()
                .is_some_and(|identity| identity.anchor_id == evidence.id)
        });
        assert_eq!(admitted, !closed, "incorrect admission for {helper}");
        if closed {
            assert!(
                evidence
                    .captures
                    .contains_key("response_control_0_definition")
            );
        }
    }
    assert!(!inventory.scan.evidence.iter().any(|e| {
        e.location.path == "app.mjs"
            && e.captures
                .get("helper_definition")
                .is_some_and(|c| c.text == "conditional")
            && e.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::NonHtmlResponse)
    }));
    fs::remove_dir_all(root).unwrap();
}
