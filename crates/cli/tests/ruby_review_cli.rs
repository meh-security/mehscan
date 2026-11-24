use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

const OPEN3_RULE: &str = "ruby-open3-command-string";
const RUNNER: &str = r#"require "open3"

class Runner
  def run(label)
    Open3.capture3("printf #{label}")
  end
end
"#;

fn mehscan(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return Value::Null;
    }
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{args:?}: {error}"))
}

fn write(root: &Path, name: &str, source: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

fn open3_evidence(scan: &Value) -> impl Iterator<Item = &Value> {
    scan["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["rule_id"] == OPEN3_RULE)
}

#[test]
fn ruby_scan_reports_exact_open3_evidence_and_scope() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    write(root, "lib/runner.rb", RUNNER);
    write(
        root,
        "lib/capture.RBW",
        r#"require('open3')
def captured(label)
  ::Open3.capture2 %Q(printf #{label})
  ::Open3.capture2e("printf #{label}")
end
"#,
    );
    write(
        root,
        "lib/controls.rb",
        r#"require "open3"
def safe_forms(label, other, command)
  Open3.capture3("printf", "%s", label)
  Open3.capture3("printf fixed")
  Open3.capture3('printf #{label}')
  Open3.capture3("printf \#{label}")
  Open3.capture3(command)
  other.capture3("printf #{label}")
end
"#,
    );
    for (file, prefix) in [
        ("local_module.rb", "require 'open3'\nmodule Open3; end\n"),
        (
            "local_constant.rb",
            "require 'open3'\nOpen3 = CustomRunner\n",
        ),
        (
            "singleton.rb",
            "require 'open3'\nclass << Open3; def capture3(text); end; end\n",
        ),
        ("local_load.rb", "require_relative 'open3'\n"),
        (
            "conditional_load.rb",
            "require 'open3' if feature_enabled\n",
        ),
        (
            "replaced_require.rb",
            "alias require require_relative\nrequire 'open3'\n",
        ),
    ] {
        write(
            root,
            file,
            &format!(r#"{prefix}Open3.capture3("printf #{{label}}")"#),
        );
    }
    write(
        root,
        "inherited.rb",
        r#"require "open3"
class Worker < ExternalBase
  def result(label)
    Open3.capture3("printf #{label}")
  end
end
"#,
    );
    write(root, "lib/broken.rb", &format!("{RUNNER}\ndef (\n"));
    for name in [
        "Gemfile",
        "Rakefile",
        "fixture.gemspec",
        "config.ru",
        "tasks/check.rake",
    ] {
        write(root, name, "# Ruby source\nlabel = 'sample'\n");
    }
    for name in [
        "spec/runner_spec.rb",
        "lib/standalone_spec.rb",
        "vendor/some_gem/runner.rb",
    ] {
        write(root, name, RUNNER);
    }

    let args = ["scan", root.to_str().unwrap(), "--format", "json"];
    let scan = mehscan(&args);
    let operations = open3_evidence(&scan).collect::<Vec<_>>();
    assert_eq!(operations.len(), 3, "{operations:?}");
    let operation = operations
        .iter()
        .find(|item| item["location"]["path"] == "lib/runner.rb")
        .unwrap();
    assert_eq!(operation["location"]["start"]["line"], 5);
    assert_eq!(operation["enclosing_symbol"], "run");
    assert_eq!(operation["captures"]["receiver"]["text"], "Open3");
    assert_eq!(
        operation["captures"]["library_load"]["text"],
        "require \"open3\""
    );
    let command = &operation["captures"]["command"];
    let start = command["location"]["start"]["byte_offset"]
        .as_u64()
        .unwrap() as usize;
    let end = command["location"]["end"]["byte_offset"].as_u64().unwrap() as usize;
    assert_eq!(&RUNNER[start..end], "\"printf #{label}\"");
    assert_eq!(command["text"], &RUNNER[start..end]);
    assert_eq!(
        operation["context"]["operand_facts"][0]["kind"],
        "process_shell_mode"
    );
    assert_eq!(
        operation["context"]["operand_facts"][0]["value"],
        "unresolved"
    );
    assert!(
        scan.get("security_paths")
            .is_none_or(|paths| paths.as_array().is_some_and(Vec::is_empty))
    );
    assert_eq!(scan["coverage"]["languages"]["ruby"]["parse_failed"], 1);
    let coverage = scan["coverage"]["files"].as_array().unwrap();
    for path in [
        "Gemfile",
        "Rakefile",
        "fixture.gemspec",
        "config.ru",
        "tasks/check.rake",
    ] {
        assert!(
            coverage.iter().any(|file| {
                file["path"] == path && file["status"] == "scanned" && file["language"] == "ruby"
            }),
            "{path}"
        );
    }
    assert!(
        coverage
            .iter()
            .any(|file| { file["path"] == "lib/broken.rb" && file["status"] == "parse_failed" })
    );

    let mut inclusive = args.to_vec();
    inclusive.push("--include-tests");
    let inclusive = mehscan(&inclusive);
    let paths = open3_evidence(&inclusive)
        .map(|item| item["location"]["path"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 5, "{paths:?}");
    assert!(paths.contains(&"spec/runner_spec.rb") && paths.contains(&"lib/standalone_spec.rb"));
    assert!(!paths.contains(&"vendor/some_gem/runner.rb"));
}

#[test]
fn ruby_native_and_source_only_work_use_the_normal_review_entry_points() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path();
    let root = base.join("source");
    let source = root.to_str().unwrap();
    write(&root, "runner.rb", RUNNER);
    write(
        &root,
        "policy.rb",
        "def same_account?(viewer, record)\n  viewer.account_id == record.account_id\nend\n",
    );
    write(
        &root,
        "other.rb",
        "class AnotherRunner\n  def run(label)\n    label\n  end\nend\n",
    );
    let python_process = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/v2-process-flow/positive/process_flow.py"),
    )
    .unwrap();
    write(&root, "process_flow.py", &python_process);

    let structural = mehscan(&[
        "investigate",
        "structural",
        source,
        "--language",
        "ruby",
        "--path",
        "runner.rb",
        "--pattern",
        "Open3.capture3($COMMAND)",
    ]);
    assert_eq!(
        structural["results"][0]["text"],
        r#"Open3.capture3("printf #{label}")"#
    );
    let symbol = mehscan(&[
        "investigate",
        "symbol",
        source,
        "--name",
        "run",
        "--path",
        "runner.rb",
    ]);
    assert_eq!(symbol["results"].as_array().unwrap().len(), 1);
    assert_eq!(symbol["results"][0]["location"]["start"]["line"], 4);
    assert_eq!(symbol["results"][0]["location"]["end"]["line"], 6);

    let inventory = base.join("inventory");
    let inventory = inventory.to_str().unwrap();
    mehscan(&[
        "investigate",
        "review-inventory",
        source,
        "--repository-key",
        "fixture:ruby-review",
        "--output",
        inventory,
    ]);
    let all = mehscan(&[
        "investigate",
        "review-inventory-list",
        "--inventory",
        inventory,
    ]);
    let entries = all["entries"].as_array().unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry["rule_id"] == OPEN3_RULE)
        .unwrap();
    let id = entry["review_id"].as_str().unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry["path"] == "process_flow.py")
    );
    assert!(entries.iter().all(|entry| entry["path"] != "policy.rb"));
    for selection in ["value", "comprehensive"] {
        let selected = mehscan(&[
            "investigate",
            "review-inventory-list",
            "--inventory",
            inventory,
            "--selection",
            selection,
        ]);
        assert!(
            selected["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["review_id"] == id),
            "{selection}: {selected}"
        );
    }

    let run = base.join("run");
    let manifest = mehscan(&[
        "investigate",
        "review-bundles",
        source,
        "--inventory",
        inventory,
        "--review-ids",
        id,
        "--output",
        run.to_str().unwrap(),
    ]);
    let request = run
        .join("requests")
        .join(manifest["bundles"][0]["filename"].as_str().unwrap());
    let bundle = request.to_str().unwrap();
    let card = mehscan(&[
        "investigate",
        "review-card",
        "--bundle",
        bundle,
        "--review-id",
        id,
    ]);
    assert_eq!(card["review_id"], id);
    assert_eq!(card["anchor"]["location"]["path"], "runner.rb");
    let draft = base.join("draft.json");
    fs::write(&draft, serde_json::to_vec(&json!({"results":[{
        "review_id":id, "decision":"needs_review", "confidence":"medium",
        "summary":"Caller authority remains open for the native command-string observation.",
        "reason":"The excerpt shows interpolation. No caller authority or runtime mode has been established.",
        "checks":["Which caller can change the label for this command?"]
    }]})).unwrap()).unwrap();
    let responses = run.join("responses");
    let response = responses.join(request.file_name().unwrap());
    let journals = base.join("journals");
    fs::create_dir(&journals).unwrap();
    mehscan(&[
        "investigate",
        "review-bundle-finalize",
        "--bundle",
        bundle,
        "--draft",
        draft.to_str().unwrap(),
        "--journal-dir",
        journals.to_str().unwrap(),
        "--source-root",
        source,
        "--output",
        response.to_str().unwrap(),
    ]);
    let report = mehscan(&[
        "report",
        "--run",
        run.to_str().unwrap(),
        "--source-root",
        source,
        "--format",
        "json",
    ]);
    assert_eq!(
        report["decision_records"][0]["response"]["decision"],
        "needs_review"
    );

    let plan = mehscan(&[
        "investigate",
        "source-review-plan",
        source,
        "--inventory",
        inventory,
    ]);
    let assignment = plan["assignments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|assignment| {
            assignment["windows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|window| window["path"] == "policy.rb")
        })
        .unwrap();
    let quote = json!({"path":"policy.rb","start_line":2,"end_line":2,
        "quote":"viewer.account_id == record.account_id"});
    let proposal = base.join("proposal.json");
    fs::write(&proposal, serde_json::to_vec(&json!({
        "plan":plan, "inspected":[], "proposals":[{
            "key":"ruby-record-owner", "assignment_id":assignment["id"],
            "capability":"authorization", "cwes":["CWE-862"],
            "question":"Does the caller enforce this account check before returning the record?",
            "mechanism":"A predicate compares accounts. Inspect whether the caller invokes it.",
            "consequence":"Account isolation depends on the caller enforcing the predicate.",
            "priority":"comprehensive", "anchor":quote, "evidence":[quote]
        }]
    })).unwrap()).unwrap();
    let output = base.join("admitted");
    let admitted = mehscan(&[
        "investigate",
        "source-review-admit",
        source,
        "--inventory",
        inventory,
        "--input",
        proposal.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(admitted["mapping"].as_object().unwrap().len(), 1);
    let inventory: Value =
        serde_json::from_slice(&fs::read(output.join("inventory.json")).unwrap()).unwrap();
    assert!(
        inventory["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["path"] == "policy.rb"
                    && entry["rule_id"] == "model-discovered-security-question"
            })
    );
}

#[test]
fn changed_ruby_inventory_scopes_work_and_keeps_unchanged_source_readable() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path();
    let root = base.join("source");
    let source = root.to_str().unwrap();
    write(&root, "runner.rb", RUNNER);
    write(&root, "other.rb", RUNNER);
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(&root)
            .args([
                "-c",
                "core.hooksPath=",
                "-c",
                "user.name=Ruby test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    };
    git(&["init", "--quiet"]);
    git(&["add", "."]);
    git(&["commit", "--quiet", "--no-gpg-sign", "-m", "Base"]);
    let before = git(&["rev-parse", "HEAD"]);
    write(&root, "runner.rb", &format!("# Current\n{RUNNER}"));
    git(&["add", "runner.rb"]);
    git(&["commit", "--quiet", "--no-gpg-sign", "-m", "Ruby change"]);
    let after = git(&["rev-parse", "HEAD"]);

    let result = mehscan(&[
        "scan",
        source,
        "--changed-from",
        &before,
        "--target",
        &after,
        "--diff-mode",
        "files",
        "--format",
        "json",
    ]);
    assert_eq!(result["impact_scope"]["included_file_count"], 1);
    let evidence = open3_evidence(&result).collect::<Vec<_>>();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0]["location"]["path"], "runner.rb");
    assert_eq!(evidence[0]["location"]["start"]["line"], 6);

    let inventory = base.join("changed");
    mehscan(&[
        "investigate",
        "review-inventory",
        source,
        "--changed-from",
        &before,
        "--target",
        &after,
        "--diff-mode",
        "files",
        "--output",
        inventory.to_str().unwrap(),
    ]);
    let plan = mehscan(&[
        "investigate",
        "source-review-plan",
        source,
        "--inventory",
        inventory.to_str().unwrap(),
    ]);
    assert!(
        plan["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|assignment| {
                assignment["windows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|window| window["path"] == "runner.rb")
            })
    );
    let source_result = mehscan(&[
        "investigate",
        "source",
        source,
        "--path",
        "other.rb",
        "--start-line",
        "4",
        "--end-line",
        "6",
    ]);
    assert!(
        source_result["results"]["text"]
            .as_str()
            .unwrap()
            .contains("Open3.capture3")
    );
}

#[test]
fn rails_ancestry_binds_exact_operands_and_keeps_framework_controls_separate() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path();
    let root = base.join("source");
    let source = root.to_str().unwrap();
    write(
        &root,
        "models/application_record.rb",
        "class ApplicationRecord < ::ActiveRecord::Base\nend\n",
    );
    write(
        &root,
        "models/article.rb",
        "class Article < ApplicationRecord\nend\n",
    );
    write(
        &root,
        "controllers/application_controller.rb",
        "class ApplicationController < ::ActionController::Base\nend\n",
    );
    write(
        &root,
        "controllers/portal/base_controller.rb",
        "module Portal\nclass BaseController < ApplicationController\nend\nend\n",
    );
    write(
        &root,
        "controllers/portal/entries_controller.rb",
        r#"require "net/http"
require "yaml"

module Portal
  class EntriesController < BaseController
    def list
      Article.where("title = #{params[:title]}")
      Article.where(published: true).order("updated_at #{params.fetch(:direction)}")
      Article.where("id = ?", params[:id])
      Article.find_by(id: params[:id])
      Article.where("title = #{normalize(params[:title])}")
      render html: params[:text].html_safe
      render html: params[:text]
      render inline: params.require(:template)
      redirect_to params[:return_to]
      redirect_to article_url(params[:id])
      send_file params[:path]
      send_file @export_path
      ::Marshal.load(params[:encoded])
      YAML.unsafe_load(params[:settings])
      YAML.safe_load(params[:settings])
      ::Net::HTTP.get(::URI.parse(params[:url]))
      ::Arel.sql("created_at #{params[:sort]}")
      ::File.read(params[:path])
      ::File.write(params[:target], "content")
      ::Kernel.system("printf #{params[:label]}")
      redirect_to configured_url, allow_other_host: true
      redirect_to default_url, allow_other_host: false
      render plain: static_text, html: params[:text].html_safe
    end

    def local(params)
      Article.where("kind = #{params[:kind]}")
      render html: params[:text].html_safe
    end
  end
end
"#,
    );
    write(
        &root,
        "controllers/lookalikes.rb",
        r#"class Unrelated
  def display(params)
    render html: params[:body].html_safe
    redirect_to params[:return_to]
    Store.where("name = #{params[:name]}")
  end
end
"#,
    );
    write(&root, "views/example.html.erb", "<%= @example.title %>\n");
    let scanned = mehscan(&["scan", source, "--format", "json"]);
    let paths = scanned["security_paths"].as_array().unwrap();
    let evidence = scanned["evidence"].as_array().unwrap();
    let mut counts = std::collections::BTreeMap::new();
    for path in paths {
        assert_eq!(path["state"], "direct");
        assert!(
            path["uncertainty_reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("runtime_dispatch_unverified"))
        );
        let sink = evidence
            .iter()
            .find(|item| item["id"] == path["sink_evidence_id"])
            .unwrap();
        let source = evidence
            .iter()
            .find(|item| item["id"] == path["source_evidence_id"])
            .unwrap();
        assert_eq!(source["rule_id"], "ruby-rails-request-parameter");
        assert_eq!(
            source["captures"]["api_binding"]["location"]["path"],
            "controllers/application_controller.rb"
        );
        assert_eq!(
            sink["location"]["path"],
            "controllers/portal/entries_controller.rb"
        );
        *counts.entry(sink["rule_id"].as_str().unwrap()).or_insert(0) += 1;
    }
    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            ("ruby-active-record-query-text", 2),
            ("ruby-arel-query-text", 1),
            ("ruby-file-read", 1),
            ("ruby-file-write", 1),
            ("ruby-kernel-command-string", 1),
            ("ruby-marshal-load", 1),
            ("ruby-net-http-request", 1),
            ("ruby-rails-inline-template", 1),
            ("ruby-rails-raw-html", 1),
            ("ruby-rails-redirect", 1),
            ("ruby-rails-send-file", 1),
            ("ruby-yaml-unsafe-load", 1),
        ])
    );
    assert!(
        evidence
            .iter()
            .all(|item| item["location"]["path"] != "controllers/lookalikes.rb")
    );
    assert_eq!(
        evidence
            .iter()
            .filter(|item| item["captures"]["redirect_policy"]["text"] == "allow_other_host: true")
            .count(),
        1
    );

    let inventory = base.join("inventory");
    mehscan(&[
        "investigate",
        "review-inventory",
        source,
        "--output",
        inventory.to_str().unwrap(),
    ]);
    let plan = mehscan(&[
        "investigate",
        "source-review-plan",
        source,
        "--inventory",
        inventory.to_str().unwrap(),
    ]);
    assert!(
        plan["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|assignment| {
                assignment["windows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|window| window["path"] == "views/example.html.erb")
            })
    );
    let view = mehscan(&[
        "investigate",
        "source",
        source,
        "--path",
        "views/example.html.erb",
        "--start-line",
        "1",
        "--end-line",
        "1",
    ]);
    assert_eq!(view["results"]["text"], "<%= @example.title %>\n");
}

#[test]
fn ruby_keeps_ambiguous_framework_bindings_out_of_direct_paths() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    write(
        root,
        "base.rb",
        "class ApplicationController < ActionController::Base\nend\n",
    );
    write(root, "reopened.rb", "class ApplicationController\nend\n");
    write(
        root,
        "shadow.rb",
        r#"module Local
  module ActiveRecord
    class Base
    end
  end
  class Record < ActiveRecord::Base
  end
end

class ReportController < ApplicationController
  def submit
    render inline: params[:template]
    Local::Record.where("name = #{params[:name]}")
  end
end
"#,
    );
    let scan = mehscan(&["scan", root.to_str().unwrap(), "--format", "json"]);
    assert!(
        scan.get("security_paths")
            .is_none_or(|paths| paths.as_array().unwrap().is_empty())
    );
    assert!(scan["evidence"].as_array().unwrap().is_empty());
}
