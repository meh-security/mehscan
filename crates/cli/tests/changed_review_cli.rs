use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

#[test]
fn files_mode_keeps_whole_file_results_without_analyzing_siblings() {
    let root = repository("whole-file");
    write(
        &root.join("lib/changed.js"),
        "// old comment\neval(request.query.code);\n",
    );
    write(&root.join("lib/sibling.js"), "eval(request.query.other);\n");
    write(&root.join(".gitattributes"), "*.js diff=unsafe\n");
    commit(&root);
    git(
        &root,
        &["config", "diff.external", "missing-external-diff-command"],
    );
    git(
        &root,
        &["config", "diff.unsafe.textconv", "missing-textconv-command"],
    );
    write(
        &root.join("lib/changed.js"),
        "// new comment\neval(request.query.code);\n",
    );
    let result = scan(&root, &["--changed-from", "HEAD", "--diff-mode", "files"]);
    assert_eq!(result["impact_scope"]["result_policy"], "changed_files");
    assert_eq!(result["impact_scope"]["included_file_count"], 1);
    assert_eq!(result["coverage"]["totals"]["scanned"], 1);
    let evidence = result["evidence"].as_array().unwrap();
    assert!(!evidence.is_empty());
    assert!(
        evidence
            .iter()
            .all(|item| item["location"]["path"] == "lib/changed.js")
    );
    assert!(
        evidence
            .iter()
            .any(|item| item["location"]["start"]["line"] == 2)
    );
}

#[test]
fn helper_only_changes_leave_unchanged_consumers_for_targeted_research() {
    let root = repository("helper-only");
    write(
        &root.join("helper.js"),
        "export function select(input) { return 'fixed'; }\n",
    );
    write(
        &root.join("consumer.js"),
        "eval(select(request.query.code));\n",
    );
    commit(&root);
    write(
        &root.join("helper.js"),
        "export function select(input) { return input; }\n",
    );
    let full = scan(&root, &[]);
    assert!(
        full["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["location"]["path"] == "consumer.js")
    );
    let changed = scan(&root, &["--changed-from", "HEAD", "--diff-mode", "files"]);
    assert_eq!(changed["impact_scope"]["included_file_count"], 1);
    assert!(changed["evidence"].as_array().unwrap().is_empty());
    assert!(
        changed["impact_scope"]["reasons"][0]
            .as_str()
            .unwrap()
            .contains("targeted context")
    );
}

#[test]
fn ignored_unsupported_and_unreadable_changes_keep_coverage_gaps() {
    let root = repository("coverage-gaps");
    write(&root.join(".gitignore"), "ignored.js\n");
    write(&root.join("ignored.js"), "const old = 1;\n");
    git(&root, &["add", "-f", "ignored.js"]);
    write(&root.join("notes.txt"), "old contract\n");
    write(&root.join("unreadable.js"), "const old = 1;\n");
    commit(&root);
    write(&root.join("ignored.js"), "eval(request.query.code);\n");
    write(&root.join("notes.txt"), "removed authorization contract\n");
    fs::write(root.join("unreadable.js"), [0xff, 0xfe]).unwrap();
    let result = scan(&root, &["--changed-from", "HEAD", "--diff-mode", "files"]);
    assert_eq!(
        result["impact_scope"]["changed_files"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(result["impact_scope"]["included_file_count"], 1);
    assert_eq!(result["coverage"]["totals"]["parse_failed"], 1);
    assert_eq!(result["coverage"]["totals"]["scanned"], 0);
    assert!(result["evidence"].as_array().unwrap().is_empty());
}

#[test]
fn unresolved_conflicts_and_unavailable_history_fail_explicitly() {
    let root = repository("unresolved");
    write(&root.join("changed.js"), "const input = 1;\n");
    commit(&root);
    assert_error(
        &root,
        &[
            "scan",
            "--changed-from",
            "missing-history",
            "--diff-mode",
            "files",
        ],
        "rev-parse",
    );
    git(&root, &["tag", "common"]);
    git(&root, &["checkout", "-b", "side"]);
    write(&root.join("changed.js"), "const input = 2;\n");
    commit(&root);
    git(&root, &["checkout", "-b", "other", "common"]);
    write(&root.join("changed.js"), "const input = 3;\n");
    commit(&root);
    let merge = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["merge", "side"])
        .output()
        .unwrap();
    assert!(!merge.status.success());
    assert_error(
        &root,
        &["scan", "--changed-from", "common", "--diff-mode", "files"],
        "unresolved Git conflict",
    );
}

#[test]
fn deletions_renames_and_configuration_never_expand_files_mode() {
    let root = repository("boundaries");
    write(&root.join("old.js"), "eval(request.query.code);\n");
    write(&root.join("removed.js"), "const control = true;\n");
    write(&root.join("other/noise.js"), "eval(request.query.other);\n");
    write(&root.join("package.json"), "{}\n");
    commit(&root);
    fs::rename(root.join("old.js"), root.join("new.js")).unwrap();
    fs::remove_file(root.join("removed.js")).unwrap();
    write(&root.join("package.json"), "{\"private\": true}\n");
    git(&root, &["add", "-A"]);
    let result = scan(&root, &["--changed-from", "HEAD", "--diff-mode", "files"]);
    let scope = &result["impact_scope"];
    assert_eq!(scope["full_scan"], false);
    assert_eq!(scope["included_file_count"], 1);
    assert!(
        scope["changed_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["status"] == "deleted")
    );
    assert!(
        scope["changed_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["previous_path"] == "old.js")
    );
    assert!(
        result["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["location"]["path"] == "new.js")
    );
}

#[test]
fn untracked_paths_are_literal_and_ignored_paths_are_not_added() {
    let root = repository("untracked");
    write(&root.join(".gitignore"), "ignored.js\n");
    commit(&root);
    write(&root.join("[input] file.js"), "eval(request.query.code);\n");
    write(&root.join("ignored.js"), "eval(request.query.secret);\n");
    // A user-configured external diff must not be invoked by the scanner.
    git(
        &root,
        &["config", "diff.external", "missing-external-diff-command"],
    );
    let result = scan(&root, &["--changed-from", "HEAD", "--diff-mode", "files"]);
    assert_eq!(
        result["impact_scope"]["changed_files"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        result["impact_scope"]["changed_files"][0]["path"],
        "[input] file.js"
    );
    assert_eq!(
        result["impact_scope"]["changed_files"][0]["status"],
        "untracked"
    );
    assert!(!result["evidence"].as_array().unwrap().is_empty());
}

#[test]
fn empty_and_deleted_only_inventories_do_not_admit_unchanged_source() {
    let root = repository("empty");
    write(
        &root.join("routes.ts"),
        "fastify.patch('/tasks/:id', async (request) => {\n  return tasks.update(request.params.id, request.body)\n})\n",
    );
    write(&root.join("removed.js"), "const control = true;\n");
    commit(&root);
    let full_run = output_dir(&root, "full");
    cli_ok(
        &root,
        &[
            "investigate",
            "review-inventory",
            "--output",
            full_run.to_str().unwrap(),
        ],
    );
    assert!(
        !read_json(&full_run.join("inventory.json"))["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for deleted in [false, true] {
        if deleted {
            fs::remove_file(root.join("removed.js")).unwrap();
        }
        let run = output_dir(&root, if deleted { "deleted" } else { "empty" });
        cli_ok(
            &root,
            &[
                "investigate",
                "review-inventory",
                "--changed-from",
                "HEAD",
                "--output",
                run.to_str().unwrap(),
            ],
        );
        let inventory = read_json(&run.join("inventory.json"));
        assert_eq!(inventory["review_count"], 0);
        assert_eq!(inventory["impact_scope"]["included_file_count"], 0);
        assert_eq!(inventory["impact_scope"]["full_scan"], false);
        assert_eq!(
            inventory["impact_scope"]["strategy"],
            if deleted {
                "changed_files_only"
            } else {
                "no_changes"
            }
        );
        if deleted {
            assert_eq!(
                inventory["impact_scope"]["changed_files"][0]["status"],
                "deleted"
            );
        }
    }
}

#[test]
fn explicit_file_list_has_no_impact_limit_and_preserves_missing_paths() {
    let root = repository("large-list");
    let mut paths = Vec::new();
    for index in 0..105 {
        let path = format!("lib/file-{index}.js");
        write(&root.join(&path), "const input = 1;\n");
        paths.push(path);
    }
    write(
        &root.join("outside/noise.js"),
        "eval(request.query.code);\n",
    );
    paths.push("removed/missing.js".into());
    let list = output_dir(&root, "files.txt");
    fs::write(&list, paths.join("\n")).unwrap();
    let result = scan(
        &root,
        &[
            "--files-from",
            list.to_str().unwrap(),
            "--diff-mode",
            "files",
            "--jobs",
            "1",
        ],
    );
    assert_eq!(result["impact_scope"]["included_file_count"], 105);
    assert_eq!(
        result["impact_scope"]["changed_files"]
            .as_array()
            .unwrap()
            .len(),
        106
    );
    assert_eq!(result["impact_scope"]["full_scan"], false);
    assert!(result["evidence"].as_array().unwrap().is_empty());
}

#[test]
fn target_requires_the_requested_clean_checkout_and_a_git_source() {
    let root = repository("target-validation");
    write(&root.join("file.js"), "const control = true;\n");
    commit(&root);
    git(&root, &["tag", "old"]);
    write(&root.join("file.js"), "eval(request.query.code);\n");
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "new"]);
    assert_error(
        &root,
        &["scan", "--changed-from", "old", "--target", "old"],
        "must match",
    );
    let result = scan(
        &root,
        &[
            "--changed-from",
            "old",
            "--target",
            "HEAD",
            "--diff-mode",
            "files",
        ],
    );
    assert_eq!(result["impact_scope"]["comparison"]["working_tree"], false);
    write(&root.join("untracked.txt"), "extra");
    assert_error(
        &root,
        &["scan", "--changed-from", "old", "--target", "HEAD"],
        "clean checkout",
    );
    assert_error(
        &root,
        &["scan", "--target", "HEAD"],
        "require --changed-from",
    );
    assert_error(&root, &["scan", "--merge-base"], "require --changed-from");
}

#[test]
fn merge_base_and_direct_release_endpoints_differ_on_divergent_history() {
    let root = repository("divergent");
    write(&root.join("common.js"), "const common = true;\n");
    commit(&root);
    git(&root, &["tag", "common"]);
    git(&root, &["checkout", "-b", "base-side"]);
    write(&root.join("base-only.js"), "const base = true;\n");
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "base-side"]);
    git(&root, &["tag", "old-release"]);
    git(&root, &["checkout", "-b", "topic", "common"]);
    write(&root.join("topic.js"), "eval(request.query.code);\n");
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "topic"]);
    git(&root, &["tag", "new-release"]);
    let direct = scan(
        &root,
        &[
            "--changed-from",
            "old-release",
            "--target",
            "new-release",
            "--diff-mode",
            "files",
        ],
    );
    assert_eq!(
        direct["impact_scope"]["changed_files"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        direct["impact_scope"]["comparison"]
            .get("merge_base_commit")
            .is_none()
    );
    let run = output_dir(&root, "merge-base");
    cli_ok(
        &root,
        &[
            "investigate",
            "review-inventory",
            "--changed-from",
            "old-release",
            "--target",
            "new-release",
            "--merge-base",
            "--output",
            run.to_str().unwrap(),
        ],
    );
    let scope = &read_json(&run.join("inventory.json"))["impact_scope"];
    assert_eq!(scope["changed_files"].as_array().unwrap().len(), 1);
    assert_eq!(scope["changed_files"][0]["path"], "topic.js");
    assert_ne!(
        scope["comparison"]["merge_base_commit"],
        scope["comparison"]["base_commit"]
    );
}

#[test]
fn moving_out_of_a_scanned_subdirectory_keeps_the_old_path() {
    let root = repository("subdirectory");
    write(&root.join("app/old.js"), "eval(request.query.code);\n");
    commit(&root);
    fs::rename(root.join("app/old.js"), root.join("outside.js")).unwrap();
    git(&root, &["add", "-A"]);
    let result = scan(
        &root.join("app"),
        &["--changed-from", "HEAD", "--diff-mode", "files"],
    );
    assert_eq!(result["impact_scope"]["changed_files"][0]["path"], "old.js");
    assert_eq!(
        result["impact_scope"]["changed_files"][0]["status"],
        "deleted"
    );
    assert!(result["evidence"].as_array().unwrap().is_empty());
}

#[test]
fn selected_bundles_and_reports_preserve_and_revalidate_scope() {
    let root = repository("report");
    write(&root.join("changed.js"), "const old = true;\n");
    write(&root.join("other/noise.js"), "eval(request.query.other);\n");
    commit(&root);
    write(&root.join("changed.js"), "eval(request.query.code);\n");
    let inventory_run = output_dir(&root, "inventory");
    cli_ok(
        &root,
        &[
            "investigate",
            "review-inventory",
            "--changed-from",
            "HEAD",
            "--output",
            inventory_run.to_str().unwrap(),
        ],
    );
    let inventory = read_json(&inventory_run.join("inventory.json"));
    let ids = inventory["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            assert_eq!(entry["path"], "changed.js");
            entry["review_id"].as_str().unwrap()
        })
        .collect::<Vec<_>>()
        .join(",");
    assert!(!ids.is_empty());
    let chunk = output_dir(&root, "chunk");
    cli_ok(
        &root,
        &[
            "investigate",
            "review-bundles",
            "--inventory",
            inventory_run.to_str().unwrap(),
            "--review-ids",
            &ids,
            "--output",
            chunk.to_str().unwrap(),
        ],
    );
    let manifest = read_json(&chunk.join("manifest.json"));
    assert_eq!(manifest["impact_scope"], inventory["impact_scope"]);
    fs::create_dir_all(chunk.join("responses")).unwrap();
    for entry in manifest["bundles"].as_array().unwrap() {
        let filename = entry["filename"].as_str().unwrap();
        let request: mehscan_core::PathReviewBundle =
            serde_json::from_slice(&fs::read(chunk.join("requests").join(filename)).unwrap())
                .unwrap();
        let request_json = serde_json::to_value(&request).unwrap();
        assert_eq!(request_json["impact_scope"], manifest["impact_scope"]);
        let response = json!({"schema_version": mehscan_core::PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION,
            "bundle_fingerprint": request.bundle_fingerprint,
            "results": request.review_ids.iter().map(|id| json!({
                "review_id": id, "selected_anchor_id": mehscan_engine::investigation::bundle_selected_anchor_id(&request, id).unwrap(),
                "decision": "needs_review", "confidence": "low",
                "summary": "Verify the exact input authority.", "checks": ["Verify input authority."],
                "investigation": {"decisive_artifacts": [], "journal_summary": null,
                    "citations": [], "reviewer_inferences": [], "reviewer_origin_leads": [], "blockers": []}
            })).collect::<Vec<_>>()});
        fs::write(
            chunk.join("responses").join(filename),
            serde_json::to_vec(&response).unwrap(),
        )
        .unwrap();
    }
    assert_error(
        &root,
        &["report", "--run", chunk.to_str().unwrap()],
        "requires --source-root",
    );
    let report = cli_json(
        &root,
        &[
            "report",
            "--run",
            chunk.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
        ],
    );
    assert_eq!(report["scan"]["impact_scope"], manifest["impact_scope"]);
    assert_eq!(
        report["scan"]["sarif_automation"]["category"],
        "mehscan/triaged/changed"
    );
    let sarif = cli_json(
        &root,
        &[
            "report",
            "--run",
            chunk.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
            "--format",
            "sarif",
        ],
    );
    assert_eq!(
        sarif["runs"][0]["properties"]["impactScope"],
        manifest["impact_scope"]
    );
    assert_eq!(
        sarif["runs"][0]["automationDetails"]["id"],
        "mehscan/triaged/changed/"
    );
    assert_eq!(
        sarif["runs"][0]["properties"]["publication"]["analysis_scope"],
        "change_comparison"
    );
    assert_eq!(
        sarif["runs"][0]["properties"]["publication"]["alert_disposition"],
        "not_established"
    );
    let explicit = cli_json(
        &root,
        &[
            "report",
            "--run",
            chunk.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
            "--format",
            "sarif",
            "--sarif-category",
            "mehscan/triaged/pr-delta",
            "--sarif-run-id",
            "attempt-2",
            "--reviewer",
            "another-reviewer",
        ],
    );
    assert_eq!(
        explicit["runs"][0]["automationDetails"]["id"],
        "mehscan/triaged/pr-delta/attempt-2"
    );
    assert_eq!(
        explicit["runs"][0]["properties"]["publication"]["analysis_scope"],
        "change_comparison"
    );
    assert_eq!(
        explicit["runs"][0]["properties"]["publication"]["alert_disposition"],
        "not_established"
    );
    assert_eq!(explicit["runs"][0]["results"], sarif["runs"][0]["results"]);
    let filename = manifest["bundles"][0]["filename"].as_str().unwrap();
    let request_path = chunk.join("requests").join(filename);
    let response_path = chunk.join("responses").join(filename);
    assert_error(
        &root,
        &[
            "investigate",
            "review-bundle-triage",
            "--bundle",
            request_path.to_str().unwrap(),
            "--responses",
            response_path.to_str().unwrap(),
        ],
        "requires --source-root",
    );
    cli_ok(
        &root,
        &[
            "investigate",
            "review-bundle-triage",
            "--bundle",
            request_path.to_str().unwrap(),
            "--responses",
            response_path.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
        ],
    );
    write(
        &root.join("other/noise.js"),
        "eval(request.query.changed_context);\n",
    );
    assert_error(
        &root,
        &[
            "investigate",
            "review-bundle-triage",
            "--bundle",
            request_path.to_str().unwrap(),
            "--responses",
            response_path.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
        ],
        "stale",
    );
    assert_error(
        &root,
        &[
            "investigate",
            "review-bundle-finalize",
            "--bundle",
            request_path.to_str().unwrap(),
            "--draft",
            "missing.json",
            "--journal-dir",
            "missing",
            "--output",
            "missing-response.json",
            "--source-root",
            root.to_str().unwrap(),
        ],
        "stale",
    );
    assert_error(
        &root,
        &[
            "report",
            "--run",
            chunk.to_str().unwrap(),
            "--source-root",
            root.to_str().unwrap(),
        ],
        "stale",
    );
    assert_error(
        &root,
        &[
            "investigate",
            "review-bundles",
            "--inventory",
            inventory_run.to_str().unwrap(),
            "--review-ids",
            &ids,
            "--output",
            chunk.to_str().unwrap(),
        ],
        "stale",
    );
}

#[test]
fn moving_a_base_ref_without_changing_sources_invalidates_the_inventory() {
    let root = repository("moved-ref");
    write(&root.join("changed.js"), "const safe = true;\n");
    commit(&root);
    git(&root, &["tag", "base"]);
    write(&root.join("changed.js"), "eval(request.query.code);\n");
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "change"]);
    let run = output_dir(&root, "inventory");
    cli_ok(
        &root,
        &[
            "investigate",
            "review-inventory",
            "--changed-from",
            "base",
            "--target",
            "HEAD",
            "--output",
            run.to_str().unwrap(),
        ],
    );
    let id = read_json(&run.join("inventory.json"))["entries"][0]["review_id"]
        .as_str()
        .unwrap()
        .to_string();
    git(&root, &["tag", "-f", "base", "HEAD"]);
    let chunk = output_dir(&root, "chunk");
    assert_error(
        &root,
        &[
            "investigate",
            "review-bundles",
            "--inventory",
            run.to_str().unwrap(),
            "--review-ids",
            &id,
            "--output",
            chunk.to_str().unwrap(),
        ],
        "stale",
    );
    assert_error(
        &root,
        &[
            "investigate",
            "review-bundles",
            "--changed-from",
            "base",
            "--output",
            chunk.to_str().unwrap(),
        ],
        "review-inventory",
    );
}

#[test]
fn same_hunks_do_not_hide_changed_unsupported_or_binary_bytes() {
    let root = repository("content-binding");
    write(&root.join("changed.js"), "const old = true;\n");
    write(&root.join("unsupported.swift"), "old contract\n");
    write(&root.join("unreadable.js"), "const old = true;\n");
    commit(&root);
    write(&root.join("changed.js"), "eval(request.query.code);\n");
    let list = output_dir(&root, "list.txt");
    fs::write(&list, "changed.js\nunsupported.swift\nunreadable.js\n").unwrap();
    for source in ["git", "list"] {
        write(&root.join("unsupported.swift"), "first contract\n");
        fs::write(root.join("unreadable.js"), [0xff, 0x00, 0x01]).unwrap();
        let run = output_dir(&root, source);
        let flags = if source == "git" {
            vec!["--changed-from", "HEAD"]
        } else {
            vec!["--files-from", list.to_str().unwrap()]
        };
        let mut args = vec![
            "investigate",
            "review-inventory",
            "--output",
            run.to_str().unwrap(),
        ];
        args.extend_from_slice(&flags);
        cli_ok(&root, &args);
        let inventory = read_json(&run.join("inventory.json"));
        let id = inventory["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == "changed.js")
            .unwrap()["review_id"]
            .as_str()
            .unwrap();
        let chunk = output_dir(&root, &format!("{source}-chunk"));
        let bundle_args = [
            "investigate",
            "review-bundles",
            "--inventory",
            run.to_str().unwrap(),
            "--review-ids",
            id,
            "--output",
            chunk.to_str().unwrap(),
        ];
        cli_ok(&root, &bundle_args);
        for binary in [false, true] {
            write(
                &root.join("unsupported.swift"),
                if binary {
                    "first contract\n"
                } else {
                    "other contract\n"
                },
            );
            fs::write(
                root.join("unreadable.js"),
                if binary {
                    [0xff, 0x00, 0x02]
                } else {
                    [0xff, 0x00, 0x01]
                },
            )
            .unwrap();
            let mut scan_args = flags.clone();
            scan_args.extend(["--diff-mode", "files"]);
            let current = scan(&root, &scan_args);
            assert_eq!(
                current["impact_scope"]["changed_files"],
                inventory["impact_scope"]["changed_files"]
            );
            assert_ne!(
                current["impact_scope"]["snapshot_fingerprint"],
                inventory["impact_scope"]["snapshot_fingerprint"]
            );
            assert_error(&root, &bundle_args, "stale");
            assert_error(
                &root,
                &[
                    "report",
                    "--run",
                    chunk.to_str().unwrap(),
                    "--source-root",
                    root.to_str().unwrap(),
                    "--allow-partial",
                    "true",
                ],
                "stale",
            );
        }
    }
}

#[test]
fn repository_identity_inherits_and_subdirectory_keys_use_repository_paths() {
    let root = repository("native-namespace");
    write(
        &root.join("app/route.js"),
        "function handle(request) { eval(request.query.code); }\n",
    );
    commit(&root);
    let full = output_dir(&root, "namespace-full");
    let sub = output_dir(&root, "namespace-sub");
    for (scan_root, output) in [(&root, &full), (&root.join("app"), &sub)] {
        cli_ok(
            scan_root,
            &[
                "investigate",
                "review-inventory",
                "--repository-key",
                "github.com/repositories/123",
                "--source-repository-key",
                "github.com/repositories/999",
                "--output",
                output.to_str().unwrap(),
            ],
        );
    }
    let a = read_json(&full.join("inventory.json"));
    let b = read_json(&sub.join("inventory.json"));
    let keys = |value: &Value| {
        value["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["identity"]["occurrence_key"].as_str().unwrap().to_owned(),
                    e["identity"]["subject_key"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert!(!keys(&a).is_empty());
    assert_eq!(keys(&a), keys(&b));
    assert_eq!(b["identity_catalog"]["repository"]["path_prefix"], "app");
    let id = a["entries"][0]["review_id"].as_str().unwrap();
    let chunk = output_dir(&root, "namespace-chunk");
    cli_ok(
        &root,
        &[
            "investigate",
            "review-bundles",
            "--inventory",
            full.to_str().unwrap(),
            "--review-ids",
            id,
            "--output",
            chunk.to_str().unwrap(),
        ],
    );
    let manifest = read_json(&chunk.join("manifest.json"));
    let request = read_json(
        &chunk
            .join("requests")
            .join(manifest["bundles"][0]["filename"].as_str().unwrap()),
    );
    assert_eq!(
        request["identity_catalog"]["repository"],
        a["identity_catalog"]["repository"]
    );
    assert_eq!(
        request["identity_catalog"]["subjects"][id]["occurrence_key"],
        a["entries"][0]["identity"]["occurrence_key"]
    );
    assert_error(
        &root,
        &[
            "investigate",
            "review-bundles",
            "--inventory",
            full.to_str().unwrap(),
            "--repository-key",
            "other:123",
            "--review-ids",
            id,
            "--output",
            chunk.to_str().unwrap(),
        ],
        "repository identity must be established",
    );
}

fn scan(root: &Path, args: &[&str]) -> Value {
    let mut all = vec!["scan", "--format", "json"];
    all.extend_from_slice(args);
    cli_json(root, &all)
}

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(args)
        .current_dir(root)
        .output()
        .unwrap()
}

#[test]
fn empty_changed_inventory_exports_bound_empty_sarif_without_claiming_resolution() {
    let root = repository("empty-sarif");
    write(
        &root.join("guard.js"),
        "function allowed(user) { return user.admin; }\n",
    );
    commit(&root);
    write(
        &root.join("guard.js"),
        "function allowed(user) { return true; }\n",
    );
    let inventory = output_dir(&root, "inventory");
    cli_ok(
        &root,
        &[
            "investigate",
            "review-inventory",
            ".",
            "--changed-from",
            "HEAD",
            "--diff-mode",
            "files",
            "--repository-key",
            "simulation:empty",
            "--output",
            inventory.to_str().unwrap(),
        ],
    );
    assert!(
        read_json(&inventory.join("inventory.json"))["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let run = output_dir(&root, "run");
    cli_ok(
        &root,
        &[
            "investigate",
            "review-bundles",
            ".",
            "--inventory",
            inventory.to_str().unwrap(),
            "--review-ids",
            "",
            "--output",
            run.to_str().unwrap(),
        ],
    );
    assert!(
        read_json(&run.join("manifest.json"))["bundles"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let sarif = cli_json(
        &root,
        &[
            "report",
            "--run",
            run.to_str().unwrap(),
            "--source-root",
            ".",
            "--format",
            "sarif",
        ],
    );
    assert!(sarif["runs"][0]["results"].as_array().unwrap().is_empty());
    assert_eq!(
        sarif["runs"][0]["properties"]["impactScope"]["changed_files"][0]["path"],
        "guard.js"
    );
    assert!(
        sarif["runs"][0]["properties"]["publication"]
            .to_string()
            .contains("not_established")
    );
    write(
        &root.join("guard.js"),
        "function allowed(user) { return false; }\n",
    );
    let stale = cli(
        &root,
        &[
            "report",
            "--run",
            run.to_str().unwrap(),
            "--source-root",
            ".",
            "--format",
            "sarif",
        ],
    );
    assert!(
        !stale.status.success(),
        "empty report must retain source freshness checks"
    );
    write(
        &root.join("guard.js"),
        "function handle(request) { eval(request.query.code); }\n",
    );
    let nonempty = output_dir(&root, "nonempty-inventory");
    cli_ok(
        &root,
        &[
            "investigate",
            "review-inventory",
            ".",
            "--changed-from",
            "HEAD",
            "--diff-mode",
            "files",
            "--output",
            nonempty.to_str().unwrap(),
        ],
    );
    assert!(
        !read_json(&nonempty.join("inventory.json"))["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_error(
        &root,
        &[
            "investigate",
            "review-bundles",
            ".",
            "--inventory",
            nonempty.to_str().unwrap(),
            "--review-ids",
            "",
            "--output",
            output_dir(&root, "invalid-empty-run").to_str().unwrap(),
        ],
        "select at least one review ID",
    );
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&inventory).unwrap();
    fs::remove_dir_all(&run).unwrap();
    fs::remove_dir_all(&nonempty).unwrap();
}

fn cli_ok(root: &Path, args: &[&str]) -> Output {
    let output = cli(root, args);
    assert!(
        output.status.success(),
        "{:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn cli_json(root: &Path, args: &[&str]) -> Value {
    serde_json::from_slice(&cli_ok(root, args).stdout).unwrap()
}

fn assert_error(root: &Path, args: &[&str], message: &str) {
    let output = cli(root, args);
    assert!(!output.status.success(), "unexpected success for {args:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "{:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn repository(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-changed-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    git(&root, &["init"]);
    git(&root, &["config", "user.name", "Mehscan Test"]);
    git(&root, &["config", "user.email", "mehscan@example.invalid"]);
    root
}

fn output_dir(root: &Path, label: &str) -> PathBuf {
    root.with_file_name(format!(
        "{}-{label}",
        root.file_name().unwrap().to_string_lossy()
    ))
}

fn write(path: &Path, source: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

fn commit(root: &Path) {
    git(root, &["add", "."]);
    git(root, &["commit", "-m", "baseline"]);
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
