use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c22")
}

#[test]
fn models_only_impact_bound_csharp_standalone_input() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("C22 fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("C22 fixture should rescan");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(counts["csharp-console-readline-source"], 6);
    assert_eq!(counts["csharp-codedom-source-compilation"], 2);
    assert_eq!(counts["csharp-fastjson-unrestricted-deserialization"], 1);
    assert_eq!(counts["csharp-fastjson-type-restriction-control"], 1);
    assert_eq!(counts["csharp-fspickler-deserialization"], 2);
    assert_eq!(counts["csharp-process-start-info-executable"], 1);
    assert_eq!(counts["csharp-process-start-info-arguments"], 1);
    assert_eq!(counts["csharp-smo-command-text"], 2);

    for capability in [
        Capability::DynamicCodeExecution,
        Capability::Deserialization,
        Capability::ProcessExecution,
        Capability::DatabaseQuery,
    ] {
        assert!(result.security_paths.iter().any(|path| {
            path.capability == capability
                && path
                    .steps
                    .iter()
                    .any(|step| step.location.path == "StandalonePositive.cs")
        }));
    }
    assert!(result.security_paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path == "StandalonePositive.cs")
    }));
    assert!(!result.evidence.iter().any(|item| {
        item.location.path == "StandaloneLookalike.cs"
            && (item.rule_id == "csharp-console-readline-source"
                || item.provenance.engine == "mehscan csharp-standalone-boundaries 1")
    }));

    let reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), true)
            .expect("C22 review material should build");
    let codedom = reviews
        .reviews
        .iter()
        .find(|review| review.candidate.sink.rule_id == "csharp-codedom-source-compilation")
        .expect("CodeDOM path should be reviewable");
    assert_eq!(
        codedom.candidate.source.capability,
        Capability::ExternalInput
    );
    assert!(
        codedom
            .open_questions
            .iter()
            .any(|question| { question.contains("interpreted as executable code") })
    );
}
