use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn assert_portable_artifact_paths(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                if matches!(name.as_str(), "path" | "uri")
                    && let Some(path) = value.as_str()
                {
                    assert!(
                        !path.starts_with(['/', '\\'])
                            && path.as_bytes().get(1) != Some(&b':')
                            && !path.split(['/', '\\']).any(|part| part == ".."),
                        "artifact path must be repository-relative: {path:?}"
                    );
                }
                assert_portable_artifact_paths(value);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                assert_portable_artifact_paths(item);
            }
        }
        _ => {}
    }
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/aliases")
}

fn selected_anchor(review: &serde_json::Value) -> serde_json::Value {
    if !review["candidate"].is_null() {
        return review["candidate"]["sink"]["id"].clone();
    }
    let ids = review["anchor_evidence_ids"]
        .as_array()
        .expect("anchor IDs");
    let evidence = review["evidence"].as_array().expect("review evidence");
    evidence
        .iter()
        .filter(|item| ids.contains(&item["id"]))
        .find(|item| item["kind"] == "sink")
        .or_else(|| {
            evidence
                .iter()
                .filter(|item| ids.contains(&item["id"]))
                .find(|item| {
                    item["kind"] == "sensitive_operation"
                        || item["kind"] == "security_configuration"
                })
        })
        .expect("selected actionable anchor")["id"]
        .clone()
}

#[test]
fn locates_files_before_reads_and_scopes_broad_reference_searches() {
    let root = fixture_root();
    let root = root.to_str().expect("fixture path should be UTF-8");
    let symbol = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "symbol",
            root,
            "--name",
            "review",
            "--path",
            "python/aliases.py",
        ])
        .output()
        .unwrap();
    assert!(symbol.status.success(), "{:?}", symbol.stderr);
    let symbol: serde_json::Value = serde_json::from_slice(&symbol.stdout).unwrap();
    assert_eq!(symbol["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        symbol["results"][0]["location"]["path"],
        "python/aliases.py"
    );
    assert_eq!(symbol["truncated"], false);
    let paths = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(["investigate", "paths", root, "--name", "aliases.py"])
        .output()
        .expect("path query should run");
    assert!(paths.status.success(), "CLI failed: {:?}", paths.stderr);
    let paths: serde_json::Value = serde_json::from_slice(&paths.stdout).unwrap();
    assert_eq!(paths["results"][0], "python/aliases.py");

    let references = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "references",
            root,
            "--symbol",
            "launch",
            "--path",
            "python/aliases.py",
        ])
        .output()
        .expect("scoped reference query should run");
    assert!(
        references.status.success(),
        "CLI failed: {:?}",
        references.stderr
    );
    let references: serde_json::Value = serde_json::from_slice(&references.stdout).unwrap();
    assert!(
        references["results"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    );
    assert!(
        references["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| { row["location"]["path"] == "python/aliases.py" })
    );
}

#[test]
fn journals_exact_investigation_queries_without_changing_stdout() {
    let root = fixture_root();
    let journal = std::env::temp_dir().join(format!(
        "mehscan-query-journal-{}.jsonl",
        std::process::id()
    ));
    let _ = fs::remove_file(&journal);
    let result = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "source",
            root.to_str().unwrap(),
            "--path",
            "python/aliases.py",
            "--start-line",
            "5",
            "--end-line",
            "7",
            "--journal",
            journal.to_str().unwrap(),
        ])
        .output()
        .expect("journaled source read should run");
    assert!(result.status.success());
    let stdout: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let lines = fs::read_to_string(&journal).unwrap();
    let rows = lines
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["operation"], "source");
    assert_eq!(rows[0]["arguments"]["--path"], "python/aliases.py");
    assert_eq!(rows[0]["output"]["results"], stdout["results"]);
    assert!(rows[0]["elapsed_ms"].is_number());
    let _ = fs::remove_file(&journal);
}

#[test]
fn compact_decisive_source_is_checked_against_the_checkout() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-process-flow");
    let run = std::env::temp_dir().join(format!("mehscan-compact-review-{}", std::process::id()));
    let generated = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundles",
            root.to_str().unwrap(),
            "--output",
            run.to_str().unwrap(),
            "--max-reviews",
            "1",
        ])
        .output()
        .unwrap();
    assert!(generated.status.success(), "{:?}", generated.stderr);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("manifest.json")).unwrap()).unwrap();
    let filename = manifest["bundles"][0]["filename"].as_str().unwrap();
    let bundle_path = run.join("requests").join(filename);
    let bundle: serde_json::Value =
        serde_json::from_slice(&fs::read(&bundle_path).unwrap()).unwrap();
    let review = &bundle["reviews"][0];
    let anchor = selected_anchor(review);
    let location = if review["candidate"].is_object() {
        review["candidate"]["sink"]["location"].clone()
    } else {
        review["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == anchor)
            .unwrap()["location"]
            .clone()
    };
    let path = location["path"].as_str().unwrap();
    let source = fs::read_to_string(root.join(path)).unwrap();
    let line = location["start"]["line"].as_u64().unwrap() as usize;
    let excerpt = source.lines().nth(line - 1).unwrap().trim();
    assert!(!excerpt.is_empty());
    let make_response = |excerpt: &str| {
        serde_json::json!({
            "schema_version": "1.3",
            "bundle_fingerprint": bundle["bundle_fingerprint"],
            "results": [{
                "review_id": review["id"],
                "selected_anchor_id": anchor,
                "decision": "issue",
                "confidence": "low",
                "summary": "The selected operation is reachable in the supplied source.",
                "checks": [],
                "investigation": {
                    "decisive_artifacts": [{
                        "artifact_id": "decisive-source",
                        "location": location,
                        "excerpt": excerpt
                    }],
                    "journal_summary": null,
                    "citations": [
                        {"artifact_id": anchor, "claim": "This is the selected operation."},
                        {"artifact_id": "decisive-source", "claim": "This is the exact source line."}
                    ],
                    "reviewer_inferences": [],
                    "reviewer_origin_leads": [],
                    "blockers": []
                }
            }]
        })
    };
    let response_path = run.join("compact-response.json");
    fs::write(
        &response_path,
        serde_json::to_vec(&make_response(excerpt)).unwrap(),
    )
    .unwrap();
    let validate = || {
        Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args([
                "investigate",
                "review-bundle-triage",
                "--bundle",
                bundle_path.to_str().unwrap(),
                "--responses",
                response_path.to_str().unwrap(),
                "--source-root",
                root.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    let validated = validate();
    assert!(
        validated.status.success(),
        "{}",
        String::from_utf8_lossy(&validated.stderr)
    );
    let concise = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-triage",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--responses",
            response_path.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
            "--summary",
            "true",
        ])
        .output()
        .unwrap();
    assert!(concise.status.success());
    let concise_report: serde_json::Value = serde_json::from_slice(&concise.stdout).unwrap();
    assert_eq!(concise_report["issue_count"], 1);
    assert!(concise_report.get("results").is_none());
    assert!(concise.stdout.len() < validated.stdout.len());
    let journal_dir = run.join("journals");
    fs::create_dir_all(&journal_dir).unwrap();
    let journal = journal_dir.join(format!("{}.jsonl", review["id"].as_str().unwrap()));
    let _ = fs::remove_file(&journal);
    let query = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "source",
            root.to_str().unwrap(),
            "--path",
            path,
            "--start-line",
            "1",
            "--end-line",
            "4",
            "--journal",
            journal.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(query.status.success());
    let final_path = run.join("final-response.json");
    let finalized = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-finalize",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--draft",
            response_path.to_str().unwrap(),
            "--journal-dir",
            journal_dir.to_str().unwrap(),
            "--output",
            final_path.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(finalized.status.success(), "{:?}", finalized.stderr);
    let final_response: serde_json::Value =
        serde_json::from_slice(&fs::read(final_path).unwrap()).unwrap();
    assert_eq!(
        final_response["results"][0]["investigation"]["journal_summary"]["query_count"],
        1
    );
    let responses_dir = run.join("responses");
    fs::create_dir_all(&responses_dir).unwrap();
    fs::copy(
        run.join("final-response.json"),
        responses_dir.join(filename),
    )
    .unwrap();
    let summary = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-summary",
            "--run",
            run.to_str().unwrap(),
            "--responses",
            responses_dir.to_str().unwrap(),
            "--allow-partial",
            "true",
            "--source-root",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(summary.status.success(), "{:?}", summary.stderr);
    let summary: serde_json::Value = serde_json::from_slice(&summary.stdout).unwrap();
    let queries = summary["family_measurements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|measurement| measurement["lookup_count"].as_u64().unwrap())
        .sum::<u64>();
    assert_eq!(queries, 1);
    fs::write(
        &response_path,
        serde_json::to_vec(&make_response("source that is not present")).unwrap(),
    )
    .unwrap();
    assert!(!validate().status.success());
}

fn web_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/web-frameworks")
}

fn csharp_breadth_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-breadth")
}

#[test]
fn investigation_commands_emit_machine_readable_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "structural",
            fixture_root()
                .to_str()
                .expect("fixture path should be UTF-8"),
            "--language",
            "python",
            "--pattern",
            "sp.Popen($COMMAND)",
            "--path",
            "python/aliases.py",
        ])
        .output()
        .expect("CLI should run");
    assert!(output.status.success(), "CLI failed: {:?}", output.stderr);
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI output should be JSON");
    assert_eq!(json["schema_version"], "2.1");
    assert_eq!(json["operation"], "run_structural_query");
    assert_eq!(json["provenance"]["resolution"], "ast");
    assert_eq!(json["results"][0]["text"], "sp.Popen(command)");

    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "units",
            fixture_root()
                .to_str()
                .expect("fixture path should be UTF-8"),
            "--capability",
            "process_execution",
            "--language",
            "python",
            "--path",
            "python/aliases.py",
            "--context-lines",
            "2",
        ])
        .output()
        .expect("CLI should run");
    assert!(output.status.success(), "CLI failed: {:?}", output.stderr);
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI output should be JSON");
    assert_eq!(json["operation"], "build_investigation_units");
    assert_eq!(json["units"].as_array().expect("units array").len(), 1);
    assert_eq!(
        json["units"][0]["selected_evidence_ids"]
            .as_array()
            .expect("ids")
            .len(),
        2
    );
    assert_eq!(json["units"][0]["anchor"]["symbol"]["name"], "review");
}

#[test]
fn native_investigation_commands_emit_typed_syntax_facts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/investigation");
    let root = root.to_str().expect("fixture path should be UTF-8");

    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "native-call-sites",
            root,
            "--callee",
            "consume",
            "--path",
            "native.cpp",
        ])
        .output()
        .expect("CLI should run");
    assert!(output.status.success(), "CLI failed: {:?}", output.stderr);
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI output should be JSON");
    assert_eq!(json["provenance"]["resolution"], "ast");
    assert_eq!(
        json["results"]["matches"][0]["call_kind"],
        "bare_identifier"
    );
    assert_eq!(
        json["results"]["matches"][0]["text"],
        "consume(packet.length)"
    );
    assert!(
        json["results"]["limitations"][0]
            .as_str()
            .expect("limitation")
            .contains("syntax inventory only")
    );
    assert_portable_artifact_paths(&json);
}

#[test]
fn filters_http_entrypoint_evidence_by_the_v05_capability() {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "evidence",
            web_fixture_root()
                .to_str()
                .expect("fixture path should be UTF-8"),
            "--capability",
            "http_request_handling",
        ])
        .output()
        .expect("CLI should run");
    assert!(output.status.success(), "CLI failed: {:?}", output.stderr);
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI output should be JSON");
    assert_eq!(json["schema_version"], "2.1");
    assert_eq!(json["operation"], "find_evidence");
    assert_eq!(
        json["results"]["evidence"]
            .as_array()
            .expect("evidence")
            .len(),
        7
    );
}

#[test]
fn reports_the_relationship_funnel_for_ai_routing() {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "funnel",
            csharp_breadth_fixture_root()
                .to_str()
                .expect("fixture path should be UTF-8"),
        ])
        .output()
        .expect("CLI should run");
    assert!(output.status.success(), "CLI failed: {:?}", output.stderr);
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI output should be JSON");
    assert_eq!(json["operation"], "relationship_funnel");
    assert_eq!(json["results"]["security_paths"], 5);
    assert_eq!(
        json["results"]["by_capability"]["outbound_network_request"]["unlinked_sinks_with_compatible_source_in_symbol"],
        1
    );
}

#[test]
fn emits_language_neutral_path_review_jobs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-process-flow");
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-jobs",
            root.to_str().expect("fixture path should be UTF-8"),
            "--context-lines",
            "2",
            "--limit",
            "3",
        ])
        .output()
        .expect("CLI should run");
    assert!(output.status.success(), "CLI failed: {:?}", output.stderr);
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI output should be JSON");
    assert_eq!(json["operation"], "build_path_review_jobs");
    assert_eq!(json["reviews"].as_array().expect("reviews").len(), 3);
    assert_eq!(json["offset"], 0);
    assert_eq!(json["next_offset"], 3);
    assert_eq!(json["include_review_material"], false);
    assert!(json["total_reviews"].as_u64().expect("total") > 3);
    assert_eq!(json["triage_contract"]["response_fields"][0], "review_id");
    assert!(
        json["reviews"][0]["facts"]
            .as_array()
            .expect("facts")
            .iter()
            .any(|fact| fact["role"] == "source_context" && fact["excerpt"].is_string())
    );

    let tasks_output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-tasks",
            root.to_str().expect("fixture path should be UTF-8"),
            "--context-lines",
            "2",
            "--limit",
            "3",
        ])
        .output()
        .expect("task CLI should run");
    assert!(
        tasks_output.status.success(),
        "CLI failed: {:?}",
        tasks_output.stderr
    );
    let tasks_json: serde_json::Value =
        serde_json::from_slice(&tasks_output.stdout).expect("tasks should be JSON");
    assert_eq!(tasks_json["tasks"].as_array().expect("tasks").len(), 3);
    assert_eq!(tasks_json["job_fingerprint"], json["fingerprint"]);
    assert!(
        tasks_json["tasks"]
            .as_array()
            .expect("tasks")
            .iter()
            .all(|task| task["job_fingerprint"] == json["fingerprint"]
                && task["triage_contract"]["response_fields"][0] == "review_id")
    );

    let second = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-jobs",
            root.to_str().expect("fixture path should be UTF-8"),
            "--context-lines",
            "2",
            "--limit",
            "3",
            "--offset",
            "3",
            "--include-review-material",
            "false",
        ])
        .output()
        .expect("second CLI page should run");
    assert!(second.status.success(), "CLI failed: {:?}", second.stderr);
    let second_json: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("second page should be JSON");
    assert_eq!(second_json["offset"], 3);
    assert_eq!(second_json["total_reviews"], json["total_reviews"]);
    assert_ne!(second_json["fingerprint"], json["fingerprint"]);
}

#[test]
fn rejects_review_pages_above_the_pagination_maximum() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-process-flow");
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-jobs",
            root.to_str().expect("fixture path should be UTF-8"),
            "--limit",
            "101",
        ])
        .output()
        .expect("CLI should reject an oversized page");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("between 1 and 100"),
        "unexpected stderr: {:?}",
        output.stderr
    );
}

#[test]
fn writes_readable_semantic_bundle_files_and_validates_one_response() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-process-flow");
    let output_dir =
        std::env::temp_dir().join(format!("mehscan-review-bundles-{}", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundles",
            root.to_str().expect("fixture path should be UTF-8"),
            "--output",
            output_dir.to_str().expect("output path should be UTF-8"),
            "--context-lines",
            "2",
            "--max-bytes",
            "65536",
        ])
        .output()
        .expect("bundle CLI should run");
    assert!(output.status.success(), "CLI failed: {:?}", output.stderr);
    let manifest: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("manifest should be JSON");
    assert_eq!(manifest["max_reviews_per_bundle"], 20);
    let first = manifest["bundles"]
        .as_array()
        .expect("manifest bundles")
        .iter()
        .find(|entry| entry["category"]["review_kind"] == "path")
        .expect("process fixture should emit a path bundle");
    assert!(first["context_text_bytes"].as_u64().is_some());
    assert!(first["repeated_context_text_bytes"].as_u64().is_some());
    let filename = first["filename"].as_str().expect("filename should exist");
    assert!(filename.starts_with("full--"));
    assert!(!filename.starts_with("bundle-"));
    let bundle_path = output_dir.join("requests").join(filename);
    assert!(bundle_path.is_file());
    assert!(output_dir.join("responses").is_dir());
    let bundle_bytes = fs::read(&bundle_path).expect("bundle request should be readable");
    assert!(
        !bundle_bytes.contains(&b'\n'),
        "model request should use compact JSON rather than indentation"
    );
    let bundle: serde_json::Value =
        serde_json::from_slice(&bundle_bytes).expect("bundle request should be JSON");
    let first_id = bundle["review_ids"][0].as_str().expect("review ID");
    let list_output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-list",
            "--bundle",
            bundle_path.to_str().unwrap(),
        ])
        .output()
        .expect("bundle list CLI should run");
    assert!(list_output.status.success());
    let listing: serde_json::Value = serde_json::from_slice(&list_output.stdout).unwrap();
    assert_eq!(listing["review_ids"], bundle["review_ids"]);
    assert!(listing.get("reviews").is_none());
    assert!(list_output.stdout.len() < bundle_bytes.len());
    let card_output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-card",
            "--bundle",
            bundle_path.to_str().expect("bundle path should be UTF-8"),
            "--review-id",
            first_id,
        ])
        .output()
        .expect("review card CLI should run");
    assert!(
        card_output.status.success(),
        "CLI failed: {:?}",
        card_output.stderr
    );
    let card: serde_json::Value =
        serde_json::from_slice(&card_output.stdout).expect("review card should be JSON");
    assert_eq!(card["review_id"], first_id);
    assert_eq!(
        card["selected_anchor_id"],
        selected_anchor(&bundle["reviews"][0])
    );
    assert!(card["anchor"]["location"]["path"].as_str().is_some());
    assert!(card_output.stdout.len() < bundle_bytes.len());
    let brief_results = bundle["reviews"]
        .as_array()
        .expect("bundle reviews")
        .iter()
        .map(|review| {
            let location = &review["candidate"]["sink"]["location"];
            serde_json::json!({
                "review_id": review["id"],
                "decision": "issue",
                "confidence": "medium",
                "summary": "The selected sink requires review of the source line.",
                "reason": "The selected source line and anchor support this decision.",
                "evidence": [{
                    "path": location["path"],
                    "start_line": location["start"]["line"],
                    "end_line": location["start"]["line"]
                }]
            })
        })
        .collect::<Vec<_>>();
    let brief_path = output_dir.join("brief.json");
    fs::write(
        &brief_path,
        serde_json::to_vec(&serde_json::json!({"results": brief_results})).unwrap(),
    )
    .expect("brief draft should write");
    let brief_response_path = output_dir.join("brief-response.json");
    let brief_final = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-finalize",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--draft",
            brief_path.to_str().unwrap(),
            "--journal-dir",
            output_dir.join("journals").to_str().unwrap(),
            "--output",
            brief_response_path.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
        ])
        .output()
        .expect("brief finalization should run");
    assert!(
        brief_final.status.success(),
        "brief CLI failed: {:?}",
        brief_final.stderr
    );
    let brief_response: serde_json::Value =
        serde_json::from_slice(&fs::read(&brief_response_path).unwrap()).unwrap();
    assert_eq!(
        brief_response["results"][0]["selected_anchor_id"],
        selected_anchor(&bundle["reviews"][0])
    );
    assert!(
        brief_response["results"][0]["investigation"]["decisive_artifacts"][0]["excerpt"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
    );
    let results = bundle["review_ids"]
        .as_array()
        .expect("review IDs")
        .iter()
        .map(|review_id| {
            let review = bundle["reviews"]
                .as_array()
                .expect("bundle reviews")
                .iter()
                .find(|review| review["id"] == *review_id)
                .expect("review should exist");
            serde_json::json!({
                "review_id": review_id,
                "selected_anchor_id": selected_anchor(review),
                "decision": "issue",
                "confidence": "medium",
                "summary": "The supplied bounded path supports this issue decision.",
                "checks": [],
                "investigation": {
                    "decisive_artifacts": [],
                    "journal_summary": null,
                    "citations": [{"artifact_id": selected_anchor(review), "claim": "This is the selected sink."}],
                    "reviewer_inferences": [],
                    "reviewer_origin_leads": [],
                    "blockers": []
                }
            })
        })
        .collect::<Vec<_>>();
    let response_path = output_dir.join("responses").join(filename);
    fs::write(
        &response_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": mehscan_core::PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION,
            "bundle_fingerprint": bundle["bundle_fingerprint"],
            "results": results
        }))
        .expect("response should serialize"),
    )
    .expect("response should write");
    let triage = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-triage",
            "--bundle",
            bundle_path.to_str().expect("bundle path should be UTF-8"),
            "--responses",
            response_path
                .to_str()
                .expect("response path should be UTF-8"),
        ])
        .output()
        .expect("bundle triage CLI should run");
    assert!(triage.status.success(), "CLI failed: {:?}", triage.stderr);
    let report: serde_json::Value =
        serde_json::from_slice(&triage.stdout).expect("triage report should be JSON");
    assert_eq!(report["complete"], true);
    assert_eq!(
        report["issue_count"].as_u64().unwrap_or(0),
        first["review_count"].as_u64().expect("review count")
    );

    for entry in manifest["bundles"]
        .as_array()
        .expect("manifest bundles")
        .iter()
        .filter(|entry| entry["filename"] != first["filename"])
    {
        let name = entry["filename"].as_str().expect("bundle filename");
        let request: serde_json::Value = serde_json::from_slice(
            &fs::read(output_dir.join("requests").join(name)).expect("request should read"),
        )
        .expect("request should be JSON");
        let results = request["review_ids"]
            .as_array()
            .expect("review IDs")
            .iter()
            .map(|review_id| {
                let review = request["reviews"]
                    .as_array()
                    .expect("bundle reviews")
                    .iter()
                    .find(|review| review["id"] == *review_id)
                    .expect("review should exist");
            let unresolved = review["decision_facts"]["unresolved"]
                    .as_array()
                    .and_then(|questions| questions.first())
                .and_then(serde_json::Value::as_str);
            let blockers = review["investigation"]["blockers"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if let Some(unresolved) = unresolved {
                serde_json::json!({
                        "review_id": review_id,
                        "selected_anchor_id": selected_anchor(review),
                        "decision": "needs_review",
                        "confidence": "medium",
                        "summary": "The supplied evidence leaves one decisive runtime fact unresolved.",
                    "checks": [unresolved],
                    "investigation": {
                        "decisive_artifacts": [],
                        "journal_summary": null,
                        "citations": [],
                        "reviewer_inferences": [],
                        "reviewer_origin_leads": [],
                        "blockers": blockers
                    }
                })
            } else {
                    serde_json::json!({
                        "review_id": review_id,
                        "selected_anchor_id": selected_anchor(review),
                        "decision": "issue",
                        "confidence": "medium",
                        "summary": "The supplied evidence establishes the reviewed weakness without an unresolved fact.",
                    "checks": [],
                    "investigation": {
                        "decisive_artifacts": [],
                        "journal_summary": null,
                        "citations": [{"artifact_id": selected_anchor(review), "claim": "This is the selected operation."}],
                        "reviewer_inferences": [],
                        "reviewer_origin_leads": [],
                        "blockers": []
                    }
                })
                }
            })
            .collect::<Vec<_>>();
        fs::write(
            output_dir.join("responses").join(name),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": mehscan_core::PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION,
                "bundle_fingerprint": request["bundle_fingerprint"],
                "results": results
            }))
            .expect("response should serialize"),
        )
        .expect("response should write");
    }
    let summary = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-summary",
            "--run",
            output_dir.to_str().expect("run path should be UTF-8"),
        ])
        .output()
        .expect("bundle summary CLI should run");
    assert!(
        summary.status.success(),
        "summary CLI failed: {:?}",
        summary.stderr
    );
    let summary_report: serde_json::Value =
        serde_json::from_slice(&summary.stdout).expect("summary report should be JSON");
    assert_eq!(summary_report["bundle_count"], manifest["bundle_count"]);
    assert_eq!(summary_report["review_count"], manifest["review_count"]);
    assert_eq!(
        summary_report["needs_review_count"].as_u64().unwrap_or(0)
            + summary_report["issue_count"].as_u64().unwrap_or(0)
            + summary_report["not_issue_count"].as_u64().unwrap_or(0),
        manifest["review_count"].as_u64().expect("review count")
    );

    let inventory_dir = output_dir.join("inventory");
    let inventory_output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-inventory",
            root.to_str().unwrap(),
            "--output",
            inventory_dir.to_str().unwrap(),
        ])
        .output()
        .expect("inventory CLI should run");
    assert!(
        inventory_output.status.success(),
        "{:?}",
        inventory_output.stderr
    );
    let ledger_path = output_dir.join("review-ledger.json");
    let ledger_output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-ledger",
            "--inventory",
            inventory_dir.to_str().unwrap(),
            "--history",
            output_dir.to_str().unwrap(),
            "--output",
            ledger_path.to_str().unwrap(),
        ])
        .output()
        .expect("ledger CLI should run");
    assert!(ledger_output.status.success(), "{:?}", ledger_output.stderr);
    let ledger: serde_json::Value =
        serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
    assert_eq!(
        ledger["reviewed"].as_object().unwrap().len(),
        manifest["review_count"].as_u64().unwrap() as usize
    );
    let remaining_output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-inventory-list",
            "--inventory",
            inventory_dir.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
        ])
        .output()
        .expect("filtered inventory CLI should run");
    assert!(
        remaining_output.status.success(),
        "{:?}",
        remaining_output.stderr
    );
    let remaining: serde_json::Value = serde_json::from_slice(&remaining_output.stdout).unwrap();
    assert_eq!(remaining["matching_count"], 0);
    let duplicate_output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundles",
            root.to_str().unwrap(),
            "--output",
            output_dir.join("duplicate").to_str().unwrap(),
            "--inventory",
            inventory_dir.to_str().unwrap(),
            "--review-ids",
            first_id,
            "--ledger",
            ledger_path.to_str().unwrap(),
        ])
        .output()
        .expect("duplicate selection CLI should run");
    assert!(!duplicate_output.status.success());
    assert!(String::from_utf8_lossy(&duplicate_output.stderr).contains("already finalized"));
    let mut wrong_ledger = ledger.clone();
    wrong_ledger["source_fingerprint"] = serde_json::json!("stale");
    let wrong_ledger_path = output_dir.join("wrong-ledger.json");
    fs::write(
        &wrong_ledger_path,
        serde_json::to_vec(&wrong_ledger).unwrap(),
    )
    .unwrap();
    let stale_output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-inventory-list",
            "--inventory",
            inventory_dir.to_str().unwrap(),
            "--ledger",
            wrong_ledger_path.to_str().unwrap(),
        ])
        .output()
        .expect("stale ledger CLI should run");
    assert!(!stale_output.status.success());
    assert!(String::from_utf8_lossy(&stale_output.stderr).contains("does not match"));

    let model_responses = output_dir.join("responses-test-model");
    fs::create_dir_all(&model_responses).expect("model response directory should be created");
    for entry in manifest["bundles"].as_array().expect("manifest bundles") {
        let name = entry["filename"].as_str().expect("bundle filename");
        fs::copy(
            output_dir.join("responses").join(name),
            model_responses.join(name),
        )
        .expect("model response should copy");
    }
    let finding_json = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "report",
            "--run",
            output_dir.to_str().expect("run path should be UTF-8"),
            "--responses",
            model_responses
                .to_str()
                .expect("response path should be UTF-8"),
            "--format",
            "json",
            "--reviewer",
            "test-model",
        ])
        .output()
        .expect("finding report CLI should run");
    assert!(
        finding_json.status.success(),
        "finding report CLI failed: {:?}",
        finding_json.stderr
    );
    let finding_report: serde_json::Value =
        serde_json::from_slice(&finding_json.stdout).expect("finding report should be JSON");
    assert_eq!(finding_report["schema_version"], "1.0");
    assert_eq!(finding_report["report_kind"], "triaged_findings");
    assert_eq!(finding_report["triage"]["reviewer"], "test-model");
    assert_eq!(finding_report["scan"]["root"], ".");
    assert_eq!(finding_report["scan"]["coverage"], manifest["coverage"]);
    assert!(
        finding_report["scan"]["scope"]
            .as_array()
            .is_some_and(|scope| !scope.is_empty())
    );
    assert_portable_artifact_paths(&finding_report);
    assert_eq!(
        finding_report["summary"]["reviewed"],
        manifest["review_count"]
    );
    assert_eq!(
        finding_report["findings"]
            .as_array()
            .expect("findings array")
            .len(),
        finding_report["summary"]["findings"]
            .as_u64()
            .expect("finding count") as usize
    );
    assert!(finding_report["findings"].as_array().is_some_and(|items| {
        items.iter().all(|item| {
            item["status"] == "issue"
                && item["severity"]["level"] == "medium"
                && item["severity"]["source"] == "fallback_default"
                && item["primary_location"]["path"].is_string()
        })
    }));

    let markdown = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "report",
            "--run",
            output_dir.to_str().expect("run path should be UTF-8"),
            "--responses",
            model_responses
                .to_str()
                .expect("response path should be UTF-8"),
            "--format",
            "markdown",
            "--reviewer",
            "test-model",
            "--include-dismissed",
            "true",
        ])
        .output()
        .expect("finding Markdown CLI should run");
    assert!(
        markdown.status.success(),
        "finding Markdown CLI failed: {:?}",
        markdown.stderr
    );
    let markdown = String::from_utf8(markdown.stdout).expect("Markdown should be UTF-8");
    assert!(markdown.starts_with("# Mehscan security report\n"));
    assert!(markdown.contains("- Reviewer: `test-model`"));
    assert!(markdown.contains("| Confirmed finding instances |"));
    assert!(markdown.contains("## Scope and limitations"));
    assert!(markdown.contains("not a unique-vulnerability total"));
    assert!(markdown.contains("## Not issues"));
    assert!(
        markdown.find("## Review next").expect("review section")
            < markdown
                .find("## Confirmed issues")
                .expect("confirmed section")
    );

    let sarif = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "report",
            "--run",
            output_dir.to_str().expect("run path should be UTF-8"),
            "--responses",
            model_responses
                .to_str()
                .expect("response path should be UTF-8"),
            "--format",
            "sarif",
        ])
        .output()
        .expect("finding SARIF CLI should run");
    let _ = fs::remove_dir_all(&output_dir);
    assert!(
        sarif.status.success(),
        "finding SARIF CLI failed: {:?}",
        sarif.stderr
    );
    let sarif: serde_json::Value =
        serde_json::from_slice(&sarif.stdout).expect("SARIF should be JSON");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(
        sarif["runs"][0]["properties"]["reportKind"],
        "triaged_findings"
    );
    assert_eq!(sarif["runs"][0]["properties"]["scanRoot"], ".");
    assert_portable_artifact_paths(&sarif);
    assert_eq!(
        sarif["runs"][0]["results"]
            .as_array()
            .expect("SARIF results")
            .len(),
        finding_report["summary"]["findings"]
            .as_u64()
            .expect("finding count") as usize
    );
    assert!(
        sarif["runs"][0]["results"]
            .as_array()
            .is_some_and(|items| { items.iter().all(|item| item["kind"] == "fail") })
    );
}

#[test]
fn diffs_reviewer_visible_bundle_content_and_scopes_model_validation() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-process-flow");
    let temp =
        std::env::temp_dir().join(format!("mehscan-review-bundle-diff-{}", std::process::id()));
    let before = temp.join("before");
    let after = temp.join("after");
    let repacked = temp.join("repacked");
    let legacy = temp.join("legacy");
    for (output, context_lines, max_reviews) in [
        (&before, "2", "20"),
        (&after, "3", "20"),
        (&repacked, "3", "1"),
        (&legacy, "3", "20"),
    ] {
        let generated = Command::new(env!("CARGO_BIN_EXE_mehscan"))
            .args([
                "investigate",
                "review-bundles",
                root.to_str().expect("fixture path should be UTF-8"),
                "--output",
                output.to_str().expect("output path should be UTF-8"),
                "--context-lines",
                context_lines,
                "--max-bytes",
                "65536",
                "--max-reviews",
                max_reviews,
            ])
            .output()
            .expect("bundle CLI should run");
        assert!(
            generated.status.success(),
            "bundle generation failed: {:?}",
            generated.stderr
        );
    }

    let changed = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-diff",
            "--before",
            before.to_str().expect("before path should be UTF-8"),
            "--after",
            after.to_str().expect("after path should be UTF-8"),
        ])
        .output()
        .expect("bundle diff should run");
    assert!(
        changed.status.success(),
        "diff failed: {:?}",
        changed.stderr
    );
    let changed: serde_json::Value =
        serde_json::from_slice(&changed.stdout).expect("diff should be JSON");
    assert_eq!(changed["contract_changed"], false);
    assert_eq!(changed["recommended_model_validation"], "changed_bundles");
    assert!(
        !changed["changed_review_ids"]
            .as_array()
            .expect("changed IDs")
            .is_empty()
    );
    assert!(
        !changed["changed_after_bundles"]
            .as_array()
            .expect("changed bundles")
            .is_empty()
    );
    let unchanged = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-diff",
            "--before",
            after.to_str().expect("before path should be UTF-8"),
            "--after",
            after.to_str().expect("after path should be UTF-8"),
        ])
        .output()
        .expect("unchanged bundle diff should run");
    assert!(
        unchanged.status.success(),
        "unchanged diff failed: {:?}",
        unchanged.stderr
    );
    let unchanged: serde_json::Value =
        serde_json::from_slice(&unchanged.stdout).expect("diff should be JSON");
    assert_eq!(unchanged["recommended_model_validation"], "not_required");
    assert_eq!(unchanged["changed_review_ids"], serde_json::json!([]));
    assert_eq!(
        unchanged["membership_changed_after_bundles"],
        serde_json::json!([])
    );
    assert_eq!(
        unchanged["unchanged_review_count"],
        changed["after"]["review_count"]
    );

    let repacked_diff = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-diff",
            "--before",
            after.to_str().expect("before path should be UTF-8"),
            "--after",
            repacked.to_str().expect("after path should be UTF-8"),
        ])
        .output()
        .expect("repacked bundle diff should run");
    let _ = fs::remove_dir_all(&temp);
    assert!(
        repacked_diff.status.success(),
        "repacked diff failed: {:?}",
        repacked_diff.stderr
    );
    let repacked_diff: serde_json::Value =
        serde_json::from_slice(&repacked_diff.stdout).expect("repacked diff should be JSON");
    assert_eq!(repacked_diff["bundle_layout_changed"], true);
    assert_eq!(repacked_diff["recommended_model_validation"], "full_pack");
    assert_eq!(repacked_diff["changed_review_ids"], serde_json::json!([]));
    assert!(
        !repacked_diff["membership_changed_after_bundles"]
            .as_array()
            .expect("membership-changed bundles")
            .is_empty()
    );
}
