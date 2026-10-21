use mehscan_core::{Capability, PathReviewBundlePayload};
use mehscan_engine::investigation::{
    build_path_review_bundles, build_review_inventory, build_selected_review_jobs,
};
use std::fs;

#[test]
fn shared_sinks_get_owned_caller_examples_without_inventing_flows_or_all_callers() {
    let root = std::env::temp_dir().join(format!("mehscan-shared-callers-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("client.mjs"),
        r#"
import fetch from 'node-fetch';
async function dispatch(url,opts) { return fetch(url,opts); }
function response(url,opts) { return dispatch(url,opts); }
export function fetchStream(url,opts) { return response(url,opts); }
export function wiped(url) { url='https://clean.example'; return dispatch(url); }
"#,
    )
    .unwrap();
    fs::write(root.join("a.mjs"),"import {fetchStream as pull} from './client.mjs';\nexport function a(input) { return pull(input.userURL); }\n").unwrap();
    fs::write(root.join("b.mjs"),"import * as client from './client.mjs';\nexport function b(input) { return client.fetchStream(input.url); }\n").unwrap();
    fs::write(
        root.join("unrelated.mjs"),
        "export function fetchStream(value) { return value; }\n",
    )
    .unwrap();
    fs::write(root.join("c.mjs"),"import {fetchStream} from './unrelated.mjs';\nexport function c(input) { return fetchStream(input.url); }\n").unwrap();
    fs::write(root.join("d.mjs"),"import {fetchStream as pull} from './client.mjs';\nexport function d(pull,input) { return pull(input.url); }\n").unwrap();
    fs::write(root.join("e.mjs"),"import {wiped} from './client.mjs';\nexport function e(input) { return wiped(input.url); }\n").unwrap();
    fs::write(root.join("cjs-client.cjs"),"const fetch=require('node-fetch');\nfunction dispatch(url) { return fetch(url); }\nexports.fetchStream=dispatch;\n").unwrap();
    fs::write(root.join("f.cjs"),"const {fetchStream: pull}=require('./cjs-client.cjs');\nfunction f(input) { return pull(input.url); }\n").unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    let primitive_ids = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| {
            e.capability == Capability::OutboundNetworkRequest
                && e.rule_id == "javascript-outbound-http"
                && matches!(e.location.path.as_str(), "client.mjs" | "cjs-client.cjs")
        })
        .map(|e| e.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let ids = inventory
        .entries
        .iter()
        .filter(|e| {
            e.identity
                .as_ref()
                .is_some_and(|i| primitive_ids.contains(&i.anchor_id))
        })
        .map(|e| e.review_id.clone())
        .collect();
    let job = build_selected_review_jobs(&root, &inventory, &ids, None).unwrap();
    for plan in job
        .reviews
        .iter()
        .map(|r| &r.investigation)
        .chain(job.observation_reviews.iter().map(|r| &r.investigation))
    {
        if plan
            .missing_facts
            .iter()
            .any(|q| q.contains("separate caller"))
        {
            assert!(
                plan.lookup_requests.iter().all(|request| {
                    request.operation == "source"
                        && request
                            .arguments
                            .get("path")
                            .is_some_and(|p| matches!(p.as_str(), "a.mjs" | "b.mjs" | "f.cjs"))
                }),
                "consumer lookup must replace generic wrapper-parameter references"
            );
        }
    }
    let facts = job
        .reviews
        .iter()
        .flat_map(|r| r.facts.iter())
        .chain(job.observation_reviews.iter().flat_map(|r| r.facts.iter()))
        .collect::<Vec<_>>();
    for path in ["a.mjs", "b.mjs", "f.cjs"] {
        assert!(
            facts
                .iter()
                .any(|f| f.role == "caller_context" && f.location.path == path),
            "missing owned caller {path}: {facts:#?}"
        );
    }
    for path in ["c.mjs", "d.mjs", "e.mjs"] {
        assert!(
            !facts
                .iter()
                .any(|f| f.role == "caller_context" && f.location.path == path),
            "unrelated/shadowed/overwritten caller {path}"
        );
    }
    assert!(
        facts.iter().any(|f| f.role == "caller_bridge_context"
            && f.location.path == "client.mjs"
            && f.excerpt.contains("dispatch(url,opts)")),
        "missing positional bridge"
    );
    assert!(
        facts
            .iter()
            .filter(|f| f.role == "caller_context")
            .all(|f| f.provenance.engine.contains("not taint")),
        "examples must not pretend to be source-sink proofs"
    );
    assert!(
        job.reviews
            .iter()
            .map(|r| &r.investigation)
            .chain(job.observation_reviews.iter().map(|r| &r.investigation))
            .any(|p| p
                .missing_facts
                .iter()
                .any(|q| q.contains("separate caller"))),
        "unresolved shared sinks need independent consumer questions"
    );
    let bundles = build_path_review_bundles(&job, None).unwrap();
    let mut projected = Vec::new();
    for bundle in &bundles.bundles {
        match &bundle.payload {
            PathReviewBundlePayload::Observation { reviews } => {
                for r in reviews {
                    projected.extend(r.facts.iter());
                }
            }
            PathReviewBundlePayload::SecurityPath { reviews } => {
                for r in reviews {
                    projected.extend(r.facts.iter());
                }
            }
        }
    }
    assert!(
        projected
            .iter()
            .any(|f| f.role == "caller_context" && !f.excerpt.is_empty()),
        "packaged investigation must preserve useful caller bytes, not only locators"
    );
    fs::remove_dir_all(root).unwrap();
}
