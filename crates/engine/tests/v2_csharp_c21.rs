use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c21")
}

#[test]
fn models_webforms_inline_output_and_exact_upload_storage() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("C21 fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("C21 fixture should rescan");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert_eq!(result.coverage.totals.scanned, 5);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(counts["csharp-webforms-inline-request-source"], 2);
    assert_eq!(counts["csharp-webforms-inline-raw-output"], 3);
    assert_eq!(counts["csharp-webforms-inline-encoding-control"], 2);
    assert_eq!(counts["csharp-webforms-literal-inline-output-control"], 1);
    assert_eq!(counts["csharp-webforms-request-validation-disabled"], 1);
    assert_eq!(counts["csharp-mvc-request-validation-disabled"], 1);
    assert_eq!(counts["csharp-webforms-uploaded-filename"], 1);
    assert_eq!(counts["csharp-webforms-upload-content"], 1);
    assert_eq!(counts["csharp-webforms-upload-file-write"], 1);
    assert_eq!(counts["csharp-webforms-posted-file-content"], 1);
    assert_eq!(counts["csharp-webforms-posted-file-save"], 1);

    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| {
                path.capability == Capability::HtmlOutput
                    && path.state == SecurityPathState::Direct
                    && path
                        .steps
                        .iter()
                        .any(|step| step.location.path == "Default.aspx")
            })
            .count(),
        2
    );
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::FileUpload
            && path
                .steps
                .iter()
                .any(|step| step.location.path == "LegacyUpload.cs")
    }));
    assert!(!result.evidence.iter().any(|item| {
        matches!(
            item.location.path.as_str(),
            "UploadLookalike.cs" | "MvcPolicyLookalike.cs"
        ) && (item.rule_id.starts_with("csharp-webforms-")
            || item.rule_id.starts_with("csharp-mvc-request-validation"))
    }));

    let reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), true)
            .expect("C21 review material should build");
    let inline = reviews
        .reviews
        .iter()
        .find(|review| review.candidate.sink.rule_id == "csharp-webforms-inline-raw-output")
        .expect("direct WebForms output should be reviewable");
    assert!(inline.facts.iter().any(|fact| {
        fact.excerpt.contains("Request[") || fact.excerpt.contains("Request.Unvalidated")
    }));
    assert!(
        inline
            .open_questions
            .iter()
            .any(|question| { question.contains("encoded for its exact HTML") })
    );
    let upload = reviews
        .reviews
        .iter()
        .find(|review| review.candidate.sink.rule_id == "csharp-webforms-posted-file-save")
        .expect("posted-file storage should be reviewable");
    assert!(upload.open_questions.iter().any(|question| {
        question.contains("server-generated storage names")
            && question.contains("content validation")
    }));
}
