use mehscan_core::{Capability, EvidenceKind};
use std::{collections::BTreeSet, fs, path::PathBuf};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn primary_key_review_requires_flow_to_the_key_not_options_or_nearby_inputs() {
    let fixture =
        Fixture(std::env::temp_dir().join(format!("mehscan-primary-key-{}", std::process::id())));
    fs::create_dir_all(&fixture.0).unwrap();
    let source = r#"
import express from 'express';
import { Record } from './models';
const app = express();
function direct(req, res) { return Record.findByPk(req.query.id); }
function withOptions(req, res) { return Record.findByPk(req.body.id, { userId: req.user.id }); }
function alias(req, res) { const id = req.query.id; return Record.findByPk(id); }
function overwritten(req, res) { let id = req.query.id; id = 'internal'; return Record.findByPk(id); }
function repository(id) { return Record.findByPk(id); }
function incidental(req, res) { const ignored = req.query.id; return Record.findByPk('fixed'); }
function optionsOnly(req, res) { return Record.findByPk('fixed', { logging: req.query.id }); }
app.get('/direct', direct);
app.post('/options', withOptions);
app.get('/alias', alias);
app.get('/overwritten', overwritten);
app.get('/incidental', incidental);
app.get('/option-input', optionsOnly);
"#;
    for extension in ["js", "ts", "tsx"] {
        fs::write(fixture.0.join(format!("app.{extension}")), source).unwrap();
    }
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    let sinks = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| {
            e.kind == EvidenceKind::Sink && e.rule_id.ends_with("-primary-key-resource-access")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        sinks.len(),
        21,
        "Unbound occurrences must remain raw evidence"
    );
    for extension in ["js", "ts", "tsx"] {
        let path = format!("app.{extension}");
        let mut reviewed = BTreeSet::new();
        for sink in sinks.iter().filter(|e| e.location.path == path) {
            assert!(sink.captures.contains_key("resource_id"));
            let admitted = inventory.entries.iter().any(|entry| {
                entry.capability == Capability::ResourceAccess
                    && entry.path == path
                    && entry.line == sink.location.start.line
            });
            if admitted {
                reviewed.insert(sink.enclosing_symbol.as_deref().unwrap());
            }
        }
        assert_eq!(
            reviewed,
            BTreeSet::from(["direct", "withOptions", "alias"]),
            "{extension}"
        );
    }
}

#[test]
fn unbound_primary_key_evidence_cannot_replace_a_mutation_authorization_question() {
    let fixture = Fixture(
        std::env::temp_dir().join(format!("mehscan-primary-key-marker-{}", std::process::id())),
    );
    fs::create_dir_all(&fixture.0).unwrap();
    fs::write(
        fixture.0.join("app.ts"),
        r#"
import express from 'express';
const app = express();
app.post('/records/update', async (req, res) => {
  const record = await Record.findByPk(internalId);
  await service.update(record);
  res.sendStatus(204);
});
"#,
    )
    .unwrap();
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id.ends_with("-primary-key-resource-access"))
    );
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.rule_id.ends_with("-primary-key-resource-access"))
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "framework-authorization-review-marker"),
        "An inventory-only lookup is not an authorization review of the mutation"
    );
}
