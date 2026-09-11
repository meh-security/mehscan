use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j4")
}

#[test]
fn relates_exact_java_upload_storage_and_second_order_process_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 7);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, evidence| {
            *counts.entry(evidence.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(counts["java-spring-controller-service-multipart-source"], 2);
    assert_eq!(counts["java-multipart-blob-validation-context"], 2);
    assert_eq!(counts["java-multipart-blob-persistence"], 2);
    assert_eq!(counts["java-uploaded-original-filename-persistence"], 1);
    assert_eq!(counts["java-multipart-content-type-validation-control"], 1);
    assert_eq!(counts["java-multipart-size-validation-control"], 1);
    assert_eq!(
        counts["java-multipart-content-signature-validation-control"],
        1
    );
    assert_eq!(
        counts["java-spring-uploaded-filename-normalization-control"],
        2
    );
    assert_eq!(counts["java-uploaded-filename-check-without-rejection"], 1);
    assert_eq!(
        counts["java-uploaded-filename-traversal-rejection-control"],
        1
    );
    assert_eq!(counts["java-stored-command-property-persistence"], 1);
    assert_eq!(counts["java-persisted-user-command-construction-source"], 1);
    assert_eq!(counts["java-proved-shell-helper-invocation"], 1);

    assert!(
        result
            .evidence
            .iter()
            .filter(|evidence| {
                evidence.rule_id == "java-spring-controller-service-multipart-source"
            })
            .all(|evidence| evidence.capability == Capability::UploadedFileContent)
    );
    let contexts = result
        .evidence
        .iter()
        .filter(|evidence| evidence.rule_id == "java-multipart-blob-validation-context")
        .collect::<Vec<_>>();
    assert!(contexts.iter().any(|evidence| {
        evidence
            .tags
            .iter()
            .any(|tag| tag == "content-signature-check-not-observed")
    }));
    assert!(contexts.iter().any(|evidence| {
        !evidence
            .tags
            .iter()
            .any(|tag| tag.ends_with("not-observed"))
    }));

    let process_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::ProcessExecution)
        .collect::<Vec<_>>();
    assert_eq!(process_paths.len(), 1);
    assert_eq!(process_paths[0].state, SecurityPathState::Unknown);
    assert_eq!(process_paths[0].cwe_candidates, ["CWE-78"]);
    assert!(
        process_paths[0]
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "shell_helper_summary_is_project_local")
    );
    assert!(!result.evidence.iter().any(|evidence| {
        evidence.location.path == "Lookalikes.java"
            && evidence.provenance.engine == "mehscan java-upload-storage-summary 1"
    }));
}

#[test]
fn persisted_user_source_semantics_resolve_redundant_origin_question() {
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(20), false)
            .expect("review job should build");
    let review = job
        .reviews
        .iter()
        .find(|review| {
            review.candidate.source.rule_id == "java-persisted-user-command-construction-source"
        })
        .expect("persisted command review");

    assert!(
        review
            .decision_facts
            .unresolved
            .iter()
            .all(|question| { !question.contains("producer, persistence, or retrieval context") })
    );
    assert!(review.decision_facts.established.iter().any(|fact| {
        fact.contains("source rule semantics explicitly establish stored, user-controlled data")
    }));
    let basis = review.review_basis.as_ref().expect("rule-derived basis");
    assert!(basis.source.tags.iter().any(|tag| tag == "stored-data"));
    assert!(basis.source.tags.iter().any(|tag| tag == "user-controlled"));
}
