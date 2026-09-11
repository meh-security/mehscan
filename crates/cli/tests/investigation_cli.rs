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

fn csharp_c10_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c10")
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
fn emits_bounded_csharp_review_neighborhoods() {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "neighborhoods",
            csharp_c10_fixture_root()
                .to_str()
                .expect("fixture path should be UTF-8"),
            "--language",
            "csharp",
            "--limit",
            "10",
        ])
        .output()
        .expect("CLI should run");
    assert!(output.status.success(), "CLI failed: {:?}", output.stderr);
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI output should be JSON");
    assert_eq!(json["operation"], "build_csharp_review_neighborhoods");
    assert!(
        json["fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("csharp-reviewpack-"))
    );
    assert_eq!(
        json["neighborhoods"]
            .as_array()
            .expect("neighborhood array")
            .len(),
        2
    );
    assert_eq!(
        json["neighborhoods"][0]["uncertainties"][0],
        serde_json::Value::Null
    );
    assert_eq!(json["triage_contract"]["response_fields"][1], "decision");
    assert_eq!(
        json["neighborhoods"][0]["candidate"],
        "Potential stored XSS through raw Razor output"
    );
    assert_eq!(
        json["neighborhoods"][0]["verification"],
        serde_json::Value::Null
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

    let results = json["reviews"]
        .as_array()
        .expect("reviews")
        .iter()
        .map(|review| {
            serde_json::json!({
                "review_id": review["id"],
                "decision": "needs_review",
                "confidence": "medium",
                "summary": "The bounded source and sink are shown, but runtime behavior remains unresolved.",
                "checks": ["Confirm the supplied value reaches the process at runtime."]
            })
        })
        .collect::<Vec<_>>();
    let response_path =
        std::env::temp_dir().join(format!("mehscan-path-review-{}.json", std::process::id()));
    fs::write(
        &response_path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "1.0",
            "job_fingerprint": json["fingerprint"],
            "results": results
        }))
        .expect("response should serialize"),
    )
    .expect("response should write");

    let partial_path = std::env::temp_dir().join(format!(
        "mehscan-path-review-partial-{}.json",
        std::process::id()
    ));
    fs::write(
        &partial_path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "1.0",
            "job_fingerprint": json["fingerprint"],
            "results": [results[0].clone()]
        }))
        .expect("partial response should serialize"),
    )
    .expect("partial response should write");
    let progress = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-progress",
            root.to_str().expect("fixture path should be UTF-8"),
            "--responses",
            partial_path
                .to_str()
                .expect("partial response path should be UTF-8"),
            "--context-lines",
            "2",
            "--limit",
            "3",
        ])
        .output()
        .expect("progress CLI should run");
    let _ = fs::remove_file(partial_path);
    assert!(
        progress.status.success(),
        "CLI failed: {:?}",
        progress.stderr
    );
    let progress_json: serde_json::Value =
        serde_json::from_slice(&progress.stdout).expect("progress should be JSON");
    assert_eq!(progress_json["submitted_count"], 1);
    assert_eq!(progress_json["remaining_count"], 2);
    assert_eq!(progress_json["complete"], false);
    let triage = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-triage",
            root.to_str().expect("fixture path should be UTF-8"),
            "--responses",
            response_path
                .to_str()
                .expect("response path should be UTF-8"),
            "--context-lines",
            "2",
            "--limit",
            "3",
        ])
        .output()
        .expect("triage CLI should run");
    let _ = fs::remove_file(response_path);
    assert!(triage.status.success(), "CLI failed: {:?}", triage.stderr);
    let triage_json: serde_json::Value =
        serde_json::from_slice(&triage.stdout).expect("triage should be JSON");
    assert_eq!(triage_json["needs_review_count"], 3);
    assert_eq!(triage_json["issue_group_count"], 0);

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
    let first = &manifest["bundles"][0];
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
            let unresolved = review["decision_facts"]["unresolved"]
                .as_array()
                .and_then(|questions| questions.first())
                .and_then(serde_json::Value::as_str)
                .expect("review should supply one unresolved fact");
            serde_json::json!({
                "review_id": review_id,
                "decision": "needs_review",
                "confidence": review["confidence_policy"]["needs_review"],
                "summary": "The supplied evidence leaves one decisive runtime fact unresolved.",
                "checks": [unresolved]
            })
        })
        .collect::<Vec<_>>();
    let response_path = output_dir.join("responses").join(filename);
    fs::write(
        &response_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "1.0",
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
    assert_eq!(report["needs_review_count"], first["review_count"]);

    for entry in manifest["bundles"]
        .as_array()
        .expect("manifest bundles")
        .iter()
        .skip(1)
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
                if let Some(unresolved) = unresolved {
                    serde_json::json!({
                        "review_id": review_id,
                        "decision": "needs_review",
                        "confidence": review["confidence_policy"]["needs_review"],
                        "summary": "The supplied evidence leaves one decisive runtime fact unresolved.",
                        "checks": [unresolved]
                    })
                } else {
                    serde_json::json!({
                        "review_id": review_id,
                        "decision": "issue",
                        "confidence": review["confidence_policy"]["issue"],
                        "summary": "The supplied evidence establishes the reviewed weakness without an unresolved fact.",
                        "checks": []
                    })
                }
            })
            .collect::<Vec<_>>();
        fs::write(
            output_dir.join("responses").join(name),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": "1.0",
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
            + summary_report["issue_count"].as_u64().unwrap_or(0),
        manifest["review_count"].as_u64().expect("review count")
    );

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
    assert!(markdown.contains("| Confirmed issues |"));
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

    let legacy_manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(legacy.join("manifest.json")).expect("legacy manifest should read"),
    )
    .expect("legacy manifest should parse");
    for entry in legacy_manifest["bundles"]
        .as_array()
        .expect("legacy bundle entries")
    {
        let request_path = legacy
            .join("requests")
            .join(entry["filename"].as_str().expect("legacy filename"));
        let mut request: serde_json::Value =
            serde_json::from_slice(&fs::read(&request_path).expect("legacy request should read"))
                .expect("legacy request should parse");
        for review in request["reviews"].as_array_mut().expect("legacy reviews") {
            review
                .as_object_mut()
                .expect("legacy review object")
                .remove("confidence_policy");
        }
        fs::write(
            request_path,
            serde_json::to_vec_pretty(&request).expect("legacy request should serialize"),
        )
        .expect("legacy request should write");
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

    let legacy_diff = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "review-bundle-diff",
            "--before",
            legacy.to_str().expect("legacy path should be UTF-8"),
            "--after",
            after.to_str().expect("after path should be UTF-8"),
        ])
        .output()
        .expect("legacy bundle diff should run");
    assert!(
        legacy_diff.status.success(),
        "legacy diff failed: {:?}",
        legacy_diff.stderr
    );
    let legacy_diff: serde_json::Value =
        serde_json::from_slice(&legacy_diff.stdout).expect("legacy diff should be JSON");
    assert_eq!(
        legacy_diff["recommended_model_validation"],
        "changed_bundles"
    );
    assert_eq!(
        legacy_diff["changed_review_ids"]
            .as_array()
            .expect("legacy changed IDs")
            .len() as u64,
        legacy_diff["after"]["review_count"]
            .as_u64()
            .expect("legacy after review count")
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

#[test]
fn validates_and_emits_compact_csharp_triage() {
    let root = csharp_c10_fixture_root();
    let neighborhoods = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "neighborhoods",
            root.to_str().expect("fixture path should be UTF-8"),
            "--language",
            "csharp",
            "--limit",
            "10",
        ])
        .output()
        .expect("neighborhood command should run");
    assert!(neighborhoods.status.success());
    let job: serde_json::Value =
        serde_json::from_slice(&neighborhoods.stdout).expect("job should be JSON");
    let results = job["neighborhoods"]
        .as_array()
        .expect("neighborhood array")
        .iter()
        .map(|neighborhood| {
            serde_json::json!({
                "neighborhood_id": neighborhood["id"],
                "decision": "needs_review",
                "confidence": "medium",
                "summary": "The candidate is credible, but one runtime fact remains unresolved.",
                "checks": ["Confirm the persisted value reaches the raw output at runtime."]
            })
        })
        .collect::<Vec<_>>();
    let response_path =
        std::env::temp_dir().join(format!("mehscan-c10-triage-{}.json", std::process::id()));
    fs::write(
        &response_path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "1.0",
            "job_fingerprint": job["fingerprint"],
            "results": results
        }))
        .expect("response should serialize"),
    )
    .expect("response fixture should write");

    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args([
            "investigate",
            "triage",
            root.to_str().expect("fixture path should be UTF-8"),
            "--language",
            "csharp",
            "--responses",
            response_path
                .to_str()
                .expect("response path should be UTF-8"),
            "--limit",
            "10",
        ])
        .output()
        .expect("triage command should run");
    fs::remove_file(&response_path).expect("temporary response should be removable");

    assert!(output.status.success(), "CLI failed: {:?}", output.stderr);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("report should be JSON");
    assert_eq!(report["schema_version"], "1.0");
    assert_eq!(report["issue_count"], 0);
    assert_eq!(report["not_issue_count"], 0);
    assert_eq!(report["needs_review_count"], 2);
    assert_eq!(report["results"][0]["decision"], "needs_review");
}
