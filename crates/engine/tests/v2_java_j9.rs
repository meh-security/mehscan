use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j9")
}

#[test]
fn models_exact_java_html_output_encoding_and_template_boundaries() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 7);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let j9 = result
        .evidence
        .iter()
        .filter(|evidence| evidence.provenance.engine == "mehscan java-html-template-policy 1")
        .collect::<Vec<_>>();
    let counts = j9.iter().fold(BTreeMap::new(), |mut counts, evidence| {
        *counts.entry(evidence.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });

    assert_eq!(counts["java-servlet-html-response-output"], 2);
    assert_eq!(counts["java-spring-responseentity-html-output"], 2);
    assert_eq!(counts["java-jsp-writer-html-output"], 1);
    assert_eq!(counts["java-owasp-contextual-encoding"], 6);
    assert_eq!(counts["java-spring-html-text-encoding"], 1);
    assert_eq!(counts["java-commons-html4-encoding"], 1);
    assert_eq!(counts["java-jsoup-safelist-html-sanitization"], 1);
    assert_eq!(counts["java-thymeleaf-render-boundary"], 1);
    assert_eq!(counts["java-freemarker-render-boundary"], 1);
    assert_eq!(counts["java-velocity-render-boundary"], 1);
    assert_eq!(j9.len(), 17);

    assert!(!j9.iter().any(|evidence| {
        matches!(
            evidence.location.path.as_str(),
            "JsonOnly.java" | "Lookalikes.java"
        )
    }));
    assert!(
        j9.iter()
            .filter(|evidence| evidence.rule_id.contains("render-boundary"))
            .all(|evidence| evidence.kind == EvidenceKind::SensitiveOperation
                && evidence.capability == Capability::HtmlOutput)
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::HtmlOutput)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 4);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        1
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Propagated)
            .count(),
        3
    );
}
