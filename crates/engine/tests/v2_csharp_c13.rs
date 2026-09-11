use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, FileStatus};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c13")
}

#[test]
fn c13_classifies_contextual_razor_escape_hatches_and_exact_encoders() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert!(result.security_paths.is_empty());
    assert!(result.coverage.files.iter().all(|file| {
        file.status == FileStatus::Scanned
            && file.language.is_none()
            && file
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no full Razor parser"))
    }));

    let c13 = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine == "mehscan razor-escape-hatch 2")
        .collect::<Vec<_>>();
    let counts = c13.iter().fold(BTreeMap::new(), |mut counts, item| {
        *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });

    assert_eq!(counts["csharp-razor-attribute-raw-output"], 6);
    assert_eq!(counts["csharp-razor-url-attribute-raw-output"], 4);
    assert_eq!(counts["csharp-razor-javascript-string-raw-output"], 4);
    assert_eq!(counts["csharp-razor-javascript-code-raw-output"], 4);
    assert_eq!(
        counts["csharp-razor-complex-attribute-raw-output-review"],
        2
    );
    assert_eq!(counts["csharp-razor-attribute-encoding-control"], 2);
    assert_eq!(counts["csharp-razor-javascript-string-encoding-control"], 2);
    assert_eq!(
        counts["csharp-razor-url-attribute-html-encoding-control"],
        1
    );
    assert_eq!(counts["csharp-razor-url-component-encoding-observation"], 1);
    assert_eq!(
        counts["csharp-razor-javascript-json-serialization-control"],
        2
    );
    assert_eq!(
        counts["csharp-razor-literal-attribute-raw-output-control"],
        1
    );
    assert_eq!(counts["csharp-razor-literal-url-raw-output-control"], 1);
    assert_eq!(
        counts["csharp-razor-literal-javascript-string-raw-output-control"],
        1
    );
    assert_eq!(
        counts["csharp-razor-literal-javascript-code-raw-output-control"],
        1
    );

    let sinks = c13
        .iter()
        .filter(|item| item.kind == EvidenceKind::Sink)
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 20);
    assert!(
        sinks
            .iter()
            .all(|item| item.capability == Capability::HtmlOutput)
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.location.path == "positive/Contexts.cshtml")
            .count(),
        5
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.location.path == "control/Encoded.cshtml")
            .count(),
        6
    );
    assert!(
        sinks
            .iter()
            .filter(|item| item.rule_id == "csharp-razor-url-attribute-raw-output")
            .all(|item| item
                .tags
                .iter()
                .any(|tag| tag == "url-scheme-validation-unresolved"))
    );

    let controls = c13
        .iter()
        .filter(|item| item.kind == EvidenceKind::Validation)
        .collect::<Vec<_>>();
    assert_eq!(controls.len(), 12);
    assert!(
        controls
            .iter()
            .all(|item| item.location.path.starts_with("control/"))
    );
    assert!(controls.iter().all(|item| item.tags.iter().any(|tag| {
        tag == "recommendation:control-present" || tag == "recommendation:review-url-policy"
    })));
    assert!(
        controls
            .iter()
            .filter(|item| item.capability == Capability::HtmlEncoding)
            .all(|item| item.related_evidence.len() == 1)
    );
    assert_eq!(
        controls
            .iter()
            .filter(|item| {
                item.rule_id == "csharp-razor-javascript-json-serialization-control"
                    && item
                        .tags
                        .iter()
                        .any(|tag| tag == "json-serializer:system-text-json")
            })
            .count(),
        1
    );

    let wrong = sinks
        .iter()
        .filter(|item| {
            item.location.path == "lookalike/WrongContext.cshtml"
                && item
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("wrong-context-encoder:"))
        })
        .collect::<Vec<_>>();
    assert_eq!(wrong.len(), 3);
    assert!(wrong.iter().all(|item| {
        item.tags
            .iter()
            .any(|tag| tag.starts_with("wrong-context-encoder:"))
    }));
    assert!(
        !controls
            .iter()
            .any(|item| item.location.path.starts_with("lookalike/"))
    );
    assert!(sinks.iter().any(|item| {
        item.location.path == "lookalike/ShadowEncoder.cshtml"
            && !item
                .tags
                .iter()
                .any(|tag| tag.starts_with("wrong-context-encoder:"))
    }));
    let complex = sinks
        .iter()
        .filter(|item| item.rule_id == "csharp-razor-complex-attribute-raw-output-review")
        .collect::<Vec<_>>();
    assert_eq!(complex.len(), 2);
    assert!(complex.iter().all(|item| {
        item.tags
            .iter()
            .any(|tag| tag == "encoding-context-unresolved")
    }));
}
