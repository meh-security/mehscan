use mehscan_core::Capability;
use mehscan_engine::investigation::{build_review_inventory, build_selected_review_jobs};
use std::fs;

#[test]
fn packets_follow_exact_helper_controls_and_only_real_configuration_accesses() {
    let root =
        std::env::temp_dir().join(format!("mehscan-packet-relevance-{}", std::process::id()));
    fs::create_dir_all(root.join("config")).unwrap();
    fs::create_dir_all(root.join(".github/actions/tool")).unwrap();
    fs::write(
        root.join("helper.mjs"),
        r#"
import {exec} from 'node:child_process';
function rejectUnsafe(cmd) {
  if (cmd.startsWith('bad')) throw new Error('rejected');
}
export function run(cmd) { rejectUnsafe(cmd); return exec(cmd); }
"#,
    )
    .unwrap();
    fs::write(
        root.join("unrelated.mjs"),
        "function rejectUnsafe(cmd) { return cmd; }",
    )
    .unwrap();
    fs::write(
        root.join("app.mjs"),
        r#"
import express from 'express';
import {run} from './helper.mjs';
const app=express();
app.get('/config/featurebase', http(api.config.featurebase));
app.post('/run', (req,res) => {
  const disabled = false;
  const mode = 'query';
  if (process.env.ALLOW_COMMANDS) {
    run(req.body.command);
  }
});
"#,
    )
    .unwrap();
    fs::write(root.join("config/live.yml"), "allowCommands: true\n").unwrap();
    fs::write(
        root.join("locale.yml"),
        "disabled: true\nenabled: true\nmode: query\nverify: true\nfeaturebase: true\n",
    )
    .unwrap();
    fs::write(
        root.join(".github/actions/tool/action.yml"),
        "shell: bash\n",
    )
    .unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    let ids = inventory
        .entries
        .iter()
        .filter(|e| e.path == "app.mjs" && e.capability == Capability::ProcessExecution)
        .map(|e| e.review_id.clone())
        .collect();
    let job = build_selected_review_jobs(&root, &inventory, &ids, None).unwrap();
    let facts = job
        .reviews
        .iter()
        .flat_map(|r| r.facts.iter())
        .chain(job.observation_reviews.iter().flat_map(|r| r.facts.iter()))
        .collect::<Vec<_>>();
    assert!(
        facts.iter().any(|f| f.symbol == "rejectUnsafe"
            && f.location.path == "helper.mjs"
            && f.excerpt.contains("startsWith('bad')")),
        "missing exact guard body: {facts:#?}"
    );
    assert!(
        !facts.iter().any(|f| f.location.path == "unrelated.mjs"),
        "same named unrelated helper is not a control"
    );
    assert!(
        facts
            .iter()
            .any(|f| f.role == "configuration_context" && f.location.path == "config/live.yml"),
        "lost explicitly accessed config key"
    );
    assert!(
        !facts.iter().any(|f| f.role == "configuration_context"
            && (f.location.path == "locale.yml" || f.location.path.starts_with(".github/"))),
        "unrelated attribute/CI word match is not configuration context"
    );
    fs::remove_dir_all(root).unwrap();
}
