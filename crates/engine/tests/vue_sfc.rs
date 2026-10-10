use mehscan_core::{EvidenceKind, FileStatus};
use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/vue-sfc-review")
}

#[test]
fn vue_scans_scripts_and_raw_templates_without_ordinary_binding_work() {
    let scan = mehscan_engine::scan_path(&fixture()).unwrap();
    assert_eq!(scan.coverage.totals.discovered, 10);
    assert_eq!(scan.coverage.totals.scanned, 6);
    assert_eq!(scan.coverage.totals.parse_failed, 4);
    for name in [
        "Raw.vue",
        "Escaped.vue",
        "Static.vue",
        "Text.vue",
        "Script.vue",
        "Unicode.vue",
    ] {
        assert!(
            scan.coverage
                .files
                .iter()
                .any(|f| f.path == name && f.status == FileStatus::Scanned),
            "{name}: {:?}",
            scan.diagnostics
        );
    }
    for name in [
        "Raw.vue",
        "Escaped.vue",
        "Unicode.vue",
        "External.vue",
        "Dual.vue",
        "Broken.vue",
    ] {
        assert!(
            scan.evidence
                .iter()
                .any(|e| e.location.path == name && e.rule_id == "vue-sfc-v-html-output"),
            "{name}"
        );
    }
    assert!(
        !scan
            .evidence
            .iter()
            .any(|e| e.location.path == "Text.vue" && e.kind == EvidenceKind::Sink)
    );
    assert!(
        !scan
            .evidence
            .iter()
            .any(|e| e.location.path == "Static.vue" && e.kind == EvidenceKind::Sink)
    );
    assert!(
        scan.evidence
            .iter()
            .any(|e| e.location.path == "Static.vue" && e.rule_id == "vue-sfc-static-html-control")
    );
    assert!(scan.evidence.iter().any(
        |e| e.location.path == "Script.vue" && e.captures.values().any(|c| c.text == "message")
    ));
    assert!(!scan.evidence.iter().any(|e| {
        e.captures
            .values()
            .any(|c| c.text.contains("tutorialSnippet") || c.text.contains("cssExample"))
    }));
    // Partial template coverage cannot hide a valid executable-script sink.
    assert!(
        scan.evidence
            .iter()
            .any(|e| e.location.path == "Partial.vue" && e.kind == EvidenceKind::Sink)
    );
    assert!(
        scan.diagnostics
            .iter()
            .any(|d| d.path.as_deref() == Some("Dual.vue") && d.message.contains("scopes"))
    );
}

#[test]
fn vue_offsets_columns_and_review_source_are_the_original_sfc() {
    let root = fixture();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    let source = std::fs::read_to_string(root.join("Unicode.vue")).unwrap();
    for evidence in scan
        .evidence
        .iter()
        .filter(|e| e.location.path == "Unicode.vue")
    {
        for location in std::iter::once(&evidence.location)
            .chain(evidence.captures.values().map(|c| &c.location))
        {
            assert_eq!(
                location.start.column,
                source[..location.start.byte_offset]
                    .rsplit('\n')
                    .next()
                    .unwrap()
                    .chars()
                    .count()
                    + 1
            );
        }
        for capture in evidence.captures.values() {
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
    }
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    assert!(
        jobs.observation_reviews.iter().any(|r| r
            .evidence
            .iter()
            .any(|e| e.location.path == "Raw.vue" && e.rule_id == "vue-sfc-v-html-output")),
        "raw template missing from review jobs"
    );
    assert!(
        !jobs
            .observation_reviews
            .iter()
            .any(|r| r.evidence.iter().any(|e| matches!(
                e.location.path.as_str(),
                "Static.vue" | "Text.vue"
            ) && e.kind == EvidenceKind::Sink))
    );
    let text = mehscan_engine::investigation::find_source_paths(&root, "Raw.vue", None).unwrap();
    assert_eq!(text.results, vec!["Raw.vue"]);
}
